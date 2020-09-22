#![allow(non_snake_case)]
use crate::errors::{ProofError, ProofResult};
use crate::gray_code::gray_code;
use crate::transcript::TranscriptProtocol;
use core::iter::{self, Iterator};
use core::ops::Mul;
use core::slice;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use merlin::Transcript;
use polynomials::Polynomial;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

static mut ENABLE_GRAY_CODE: bool = false;

/// A collection of generator points that can be used to compute various proofs
/// in this module. To create an instance of [`ProofGens`] it is recommended to
/// call ProofGens::new(`n`), where `n` is the number of bits to be used in
/// proofs and verifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGens {
    pub n_bits: usize,
    G: RistrettoPoint,
    H: Vec<RistrettoPoint>,
}

/// A bit commitment proof. This is used as part of a [`OneOfManyProof`] and
/// not meant for use on its own. A zero knowledge proof that the prover knows
/// the openings of commitments to a sequence of bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitProof {
    A: RistrettoPoint,
    C: RistrettoPoint,
    D: RistrettoPoint,
    f1_j: Vec<Scalar>,
    z_A: Scalar,
    z_C: Scalar,
}

/// A zero knowledge proof of membership in a set. A prover can convince a
/// verifier that he knows the index of a commitment within a set of
/// commitments, and the opening of that commitment,
/// without revealing any information about the commitment or its location
/// within the set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneOfManyProof {
    B: RistrettoPoint,
    bit_proof: BitProof,
    G_k: Polynomial<RistrettoPoint>,
    z: Scalar,
}

impl ProofGens {
    /// Create a new instance of [`ProofGens`] with enough generator points to
    /// support proof and verification over an `n_bit` sized set.
    ///
    /// ```
    /// # use one_of_many_proofs::proofs::ProofGens;
    /// // Support 10 bit membership proofs
    /// let gens = ProofGens::new(10);
    /// ```
    pub fn new(n_bits: usize) -> ProofResult<ProofGens> {
        if n_bits <= 1 {
            return Err(ProofError::SetIsTooSmall);
        }
        if n_bits > 32 {
            return Err(ProofError::SetIsTooLarge);
        };

        // Compute enough generator points to support vector commitments of
        // length 2*n: r*G + v[0]*H[0] + ... + v[2n-1]*H[2n-1]
        //
        // G       = Ristretto Base Point
        // H[0]    = hash(G)
        // H[1]    = hash(H[0])
        //  .           .
        //  .           .
        //  .           .
        // H[2n-1] = hash(H[2n-2])
        let mut gens = ProofGens {
            n_bits,
            G: constants::RISTRETTO_BASEPOINT_POINT,
            H: Vec::with_capacity(2 * n_bits),
        };
        gens.H.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
            gens.G.compress().as_bytes(),
        ));
        for i in 1..(2 * n_bits) {
            gens.H.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
                gens.H[i - 1].compress().as_bytes(),
            ));
        }
        Ok(gens)
    }

    /// Returns the maximum set size that can be processed in a proof or
    /// verification. For example, a 10 bit proof would only be able to support
    /// proofs over a set with at most `2^10 = 1024` members. Note, proofs over
    /// smaller sets will be extended by repeating the first member.
    pub fn max_set_size(&self) -> usize {
        2usize.checked_pow(self.n_bits as u32).unwrap()
    }

    /// Create a pedersen commitment, with value `v` and blinding factor `r`.
    pub fn commit(&self, v: &Scalar, r: &Scalar) -> ProofResult<RistrettoPoint> {
        Ok(v * self.H[0] + r * self.G)
    }

    /// Commit to the bits in `l`, and generate the corresponding proof.
    /// Note, `l` must be within the supported set size, eg, for an `n` bit
    /// proof, `l` mus reside within the range: 0 <= `l` < 2^`n`.
    ///
    /// This proof uses a [`merlin`] transcript to generate a challenge
    /// scalar for use as a non-interactive proof protocol.
    ///
    /// This function returns the bit commitment, `B`, its assosciated
    /// [`BitProof`], and the challenge scalar `x`.
    ///
    /// ```
    /// # use rand::rngs::OsRng; // You should use a more secure RNG
    /// # use one_of_many_proofs::proofs::ProofGens;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use merlin::Transcript;
    /// // Compute the generators necessary for 5 bit proofs
    /// let gens = ProofGens::new(5).unwrap();
    /// let l = 7; // Some index within the range 0 <= `l` <= 2^5
    ///
    /// // The proof requires us to provide random noise values. For secure
    /// // applications, be sure to use a more secure RNG.
    /// let a_j = (0..gens.n_bits)
    ///     .map(|_| Scalar::random(&mut OsRng))
    ///     .collect::<Vec<Scalar>>();
    ///
    /// // Create a new transcript and compute the bit commitment and its proof
    /// let mut t = Transcript::new(b"doctest example");
    /// let (B, proof, x) = gens.commit_bits(&mut t, l, &a_j).unwrap();
    /// ```
    pub fn commit_bits(
        &self,
        transcript: &mut Transcript,
        l: usize,
        a_j: &Vec<Scalar>,
    ) -> ProofResult<(RistrettoPoint, BitProof, Scalar)> {
        if l >= self.max_set_size() {
            return Err(ProofError::IndexOutOfBounds);
        }

        transcript.bit_proof_domain_sep(self.n_bits as u64);

        // Create a `TranscriptRng` from the high-level witness data
        //
        // The prover wants to rekey the RNG with its witness data (`l`).
        let mut rng = {
            let mut builder = transcript.build_rng();

            // Commit to witness data
            builder = builder.rekey_with_witness_bytes(b"l", Scalar::from(l as u64).as_bytes());

            use rand::thread_rng;
            builder.finalize(&mut thread_rng())
        };

        let b_j_i = (0..2)
            .map(|i| {
                (0..self.n_bits)
                    .map(|j| Scalar::from(delta(bit(l, j), i) as u32))
                    .collect()
            })
            .collect::<Vec<Vec<Scalar>>>();

        let r_A = Scalar::random(&mut rng);
        let r_B = Scalar::random(&mut rng);
        let r_C = Scalar::random(&mut rng);
        let r_D = Scalar::random(&mut rng);
        let a_j_i = iter::once(a_j.clone())
            .chain(iter::once(a_j.iter().map(|a| -a).collect()))
            .collect::<Vec<Vec<Scalar>>>();
        let A = a_j_i.iter().flatten().commit(&self, &r_A)?;
        let B = b_j_i.iter().flatten().commit(&self, &r_B)?;
        let C = a_j_i
            .iter()
            .flatten()
            .zip(b_j_i.iter().flatten())
            .map(|(a, b)| a * (Scalar::one() - Scalar::from(2u32) * b))
            .commit(&self, &r_C)?;
        let D = a_j_i.iter().flatten().map(|a| -a * a).commit(&self, &r_D)?;

        transcript.validate_and_append_point(b"A", &A.compress())?;
        transcript.validate_and_append_point(b"B", &B.compress())?;
        transcript.validate_and_append_point(b"C", &C.compress())?;
        transcript.validate_and_append_point(b"D", &D.compress())?;

        let x = transcript.challenge_scalar(b"bit-proof-challenge");

        let f1_j = a_j_i[1]
            .iter()
            .zip(b_j_i[1].iter())
            .map(|(a, b)| b * x + a)
            .collect();
        let z_A = r_B * x + r_A;
        let z_C = r_C * x + r_D;

        for f in &f1_j {
            transcript.append_scalar(b"f1_j", f);
        }
        transcript.append_scalar(b"z_A", &z_A);
        transcript.append_scalar(b"z_C", &z_C);

        Ok((
            B,
            BitProof {
                A,
                C,
                D,
                f1_j,
                z_A,
                z_C,
            },
            x,
        ))
    }

    /// Verify a bit commitment proof.
    ///
    /// ```
    /// # use rand::rngs::OsRng; // You should use a more secure RNG
    /// # use one_of_many_proofs::proofs::ProofGens;
    /// # use curve25519_dalek::scalar::Scalar;
    /// # use merlin::Transcript;
    /// # let gens = ProofGens::new(5).unwrap();
    /// # let l = 7; // Some index within the range 0 <= `l` <= 2^5
    /// # let a_j = (0..gens.n_bits)
    /// #    .map(|_| Scalar::random(&mut OsRng))
    /// #    .collect::<Vec<Scalar>>();
    /// # let mut t = Transcript::new(b"doctest example");
    /// # let (B, proof, _) = gens.commit_bits(&mut t, l, &a_j).unwrap();
    /// // Create new transcript and verify a bit commitment against its proof
    /// let mut t = Transcript::new(b"doctest example");
    /// assert!(gens.verify_bits(&mut t, &B, &proof).is_ok());
    /// ```
    pub fn verify_bits(
        &self,
        transcript: &mut Transcript,
        B: &RistrettoPoint,
        proof: &BitProof,
    ) -> ProofResult<Scalar> {
        transcript.bit_proof_domain_sep(self.n_bits as u64);

        transcript.validate_and_append_point(b"A", &proof.A.compress())?;
        transcript.validate_and_append_point(b"B", &B.compress())?;
        transcript.validate_and_append_point(b"C", &proof.C.compress())?;
        transcript.validate_and_append_point(b"D", &proof.D.compress())?;

        let x = transcript.challenge_scalar(b"bit-proof-challenge");

        for f in &proof.f1_j {
            transcript.append_scalar(b"f1_j", f);
        }
        transcript.append_scalar(b"z_A", &proof.z_A);
        transcript.append_scalar(b"z_C", &proof.z_C);

        // Verify proof size
        if proof.f1_j.len() != self.n_bits {
            return Err(ProofError::InvalidProofSize);
        }

        // Verify all scalars are canonical
        for f in &proof.f1_j {
            if !f.is_canonical() {
                return Err(ProofError::InvalidScalar(*f));
            }
        }
        if !proof.z_A.is_canonical() {
            return Err(ProofError::InvalidScalar(proof.z_A));
        }
        if !proof.z_C.is_canonical() {
            return Err(ProofError::InvalidScalar(proof.z_C));
        }

        // Inflate f1_j to include reconstructed f0_j vector
        let f_j_i = iter::once(proof.f1_j.iter().map(|f| x - f).collect())
            .chain(iter::once(proof.f1_j.clone()))
            .collect::<Vec<Vec<Scalar>>>();

        // Verify relation R1
        if x * B + proof.A != f_j_i.iter().flatten().commit(&self, &proof.z_A)? {
            return Err(ProofError::VerificationFailed);
        }
        let r1 = f_j_i
            .iter()
            .map(|f_j| f_j.iter().map(|f| f * (x - f)))
            .flatten()
            .commit(&self, &proof.z_C)?;
        if x * proof.C + proof.D != r1 {
            return Err(ProofError::VerificationFailed);
        }
        Ok(x)
    }
}

pub trait OneOfManyProofs {
    //! Trait for computing and verifying OneOfMany zero-knowledge membership
    //! proofs over a set of points. Each method is designed to iterate over a
    //! set of [`RistrettoPoint`]s representing pedersen commitments. A prover
    //! should know the opening of one commitment in the set, and the index of
    //! that commitment within the set.
    //!
    //! # Proof of knowledge of a commitment that opens to zero
    //! The `prove()` and `verify()` methods may be used to compute and verify
    //! membership of a commitment that opens to zero within a specified set of
    //! commitments. Proofs for commitments are demonstrated further below.
    //!
    //! ```
    //! # use rand::rngs::OsRng; // You should use a more secure RNG
    //! # use one_of_many_proofs::proofs::{ProofGens, OneOfManyProofs};
    //! # use curve25519_dalek::scalar::Scalar;
    //! # use curve25519_dalek::ristretto::RistrettoPoint;
    //! # use merlin::Transcript;
    //! #
    //! // Set up proof generators
    //! let gens = ProofGens::new(5).unwrap();
    //!
    //! // Create the prover's commitment to zero
    //! let l: usize = 3; // The prover's commitment will be third in the set
    //! let v = Scalar::zero();
    //! let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
    //! let C_l = gens.commit(&v, &r).unwrap();
    //!
    //! // Build a random set containing the prover's commitment at index `l`
    //! let mut set = (1..gens.max_set_size())
    //!     .map(|_| RistrettoPoint::random(&mut OsRng))
    //!     .collect::<Vec<RistrettoPoint>>();
    //! set.insert(l, C_l);
    //!
    //! // Compute a `OneOfMany` membership proof for this commitment
    //! let mut t = Transcript::new(b"OneOfMany-Test");
    //! let proof = set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap();
    //!
    //! // Verify this membership proof, without any knowledge of `l` or `r`.
    //! assert!(set
    //!     .iter()
    //!     .verify(&gens, &mut t.clone(), &proof)
    //!     .is_ok());
    //! ```
    //!
    //! # Proof of knowledge of a commitment that opens to any value
    //! This is an extension of the OneOfMany proof protocol, to enable proof
    //! of knowledge of a commitment to any value within the set.
    //!
    //! If the prover knows the index, `l`, and opening of some commitment,
    //! `C_l`, within a set of commitments, then the prover can prove this
    //! knowledge, and also prove that some new commitment, `C_new`, commits to
    //! the same value as `C_l`.
    //!
    //! The basic concept is that `C_new` will be supplied as an offset in the
    //! proof computation. This offset will be subtracted from every member in
    //! the set before computing a OneOfMany proof. Since, `C_new` commits to
    //! the same value as `C_l`, the result after subtraction will yield a
    //! commitment to 0 at index `l` within the set. This commitment to 0 can
    //! now be used to compute a OneOfMany proof of membership.
    //!
    //! > Note: the resultant commitment to zero is blinded by `r - r_new`, and
    //! this value must be supplied instead of `r`, to compute the proof.
    //!
    //! ```
    //! # use rand::rngs::OsRng; // You should use a more secure RNG
    //! # use one_of_many_proofs::proofs::{ProofGens, OneOfManyProofs};
    //! # use curve25519_dalek::scalar::Scalar;
    //! # use curve25519_dalek::ristretto::RistrettoPoint;
    //! # use merlin::Transcript;
    //! #
    //! // Set up proof generators
    //! let gens = ProofGens::new(5).unwrap();
    //!
    //! // Create the prover's commitment to a random value
    //! let l: usize = 3; // The prover's commitment will be third in the set
    //! let v = Scalar::random(&mut OsRng); // You should use a more secure RNG
    //! let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
    //! let C_l = gens.commit(&v, &r).unwrap();
    //!
    //! // Build a random set containing the prover's commitment at index `l`
    //! let mut set = (1..gens.max_set_size())
    //!     .map(|_| RistrettoPoint::random(&mut OsRng))
    //!     .collect::<Vec<RistrettoPoint>>();
    //! set.insert(l, C_l);
    //!
    //! // Create a new commitment to the same value as `C_l`
    //! let r_new = Scalar::random(&mut OsRng); // You should use a more secure RNG
    //! let C_new = gens.commit(&v, &r_new).unwrap();
    //!
    //! // Compute a `OneOfMany` membership proof for this commitment
    //! let mut t = Transcript::new(b"OneOfMany-Test");
    //! let proof = set.iter().prove_with_offset(&gens, &mut t.clone(), l, &(r - r_new), Some(&C_new)).unwrap();
    //!
    //! // Verify this membership proof, without any knowledge of `l` or `r`.
    //! assert!(set
    //!     .iter()
    //!     .verify_with_offset(&gens, &mut t.clone(), &proof, Some(&C_new))
    //!     .is_ok());
    //! ```

    /// Prove knowledge of a commitment opening to zero. The prover must
    /// provide the index `l` of a commitment within the set that opens to
    /// zero, and  also its blinding factor, `r`.
    ///
    /// Note: this is just a convenience wrapper around `prove_with_offset()`.
    fn prove(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        l: usize,
        r: &Scalar,
    ) -> ProofResult<OneOfManyProof> {
        self.prove_with_offset(gens, transcript, l, r, None)
    }

    /// Verify a proof of knowledge of a commitment opening to zero. This
    /// verification will only succeed if the proven commitment opens to zero.
    ///
    /// Note: this is just a convenience wrapper around `verify_with_offset()`.
    fn verify(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        proof: &OneOfManyProof,
    ) -> ProofResult<()> {
        self.verify_with_offset(gens, transcript, proof, None)
    }

    /// Prove knowledge of a commitment opening to any value.
    fn prove_with_offset(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        l: usize,
        r: &Scalar,
        offset: Option<&RistrettoPoint>,
    ) -> ProofResult<OneOfManyProof>;

    /// Verify a proof of knowledge of a commitment opening to any value.
    fn verify_with_offset(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        proof: &OneOfManyProof,
        offset: Option<&RistrettoPoint>,
    ) -> ProofResult<()> {
        self.verify_batch_with_offsets(
            gens,
            transcript,
            slice::from_ref(&proof),
            slice::from_ref(&offset),
        )
    }

    /// Batch verification of membership proofs
    fn verify_batch(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        proofs: &[OneOfManyProof],
    ) -> ProofResult<()> {
        self.verify_batch_with_offsets(gens, transcript, proofs, &vec![None; proofs.len()])
    }

    /// Batch verification of membership proofs
    fn verify_batch_with_offsets(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        proofs: &[OneOfManyProof],
        offsets: &[Option<&RistrettoPoint>],
    ) -> ProofResult<()>;
}

impl<'a, I> OneOfManyProofs for I
where
    I: Iterator<Item = &'a RistrettoPoint> + Clone,
{
    fn prove_with_offset(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        l: usize,
        r: &Scalar,
        offset: Option<&RistrettoPoint>,
    ) -> ProofResult<OneOfManyProof> {
        transcript.one_of_many_proof_domain_sep(gens.n_bits as u64);

        // Create a `TranscriptRng` from the high-level witness data
        //
        // The prover wants to rekey the RNG with its witness data (`l` and `r`).
        let mut rng = {
            let mut builder = transcript.build_rng();

            // Commit to witness data
            builder = builder.rekey_with_witness_bytes(b"l", Scalar::from(l as u64).as_bytes());
            builder = builder.rekey_with_witness_bytes(b"r", r.as_bytes());

            use rand::thread_rng;
            builder.finalize(&mut thread_rng())
        };

        if l > gens.max_set_size() {
            return Err(ProofError::IndexOutOfBounds);
        }

        let rho_k = (0..gens.n_bits)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<Scalar>>();
        let a_j = (0..gens.n_bits)
            .map(|_| Scalar::random(&mut rng))
            .collect::<Vec<Scalar>>();
        let a_j_i = iter::once(a_j.clone())
            .chain(iter::once(a_j.iter().map(|a| -a).collect()))
            .collect::<Vec<Vec<Scalar>>>();

        let mut G_k = Polynomial::from(
            rho_k
                .iter()
                .map(|rho| gens.commit(&Scalar::zero(), rho).unwrap())
                .collect::<Vec<RistrettoPoint>>(),
        );
        let mut i = 0;
        self.clone()
            .map(|&C_i| if let Some(O) = offset { C_i - O } else { C_i })
            .for_each(|C_i| {
                let p_i = compute_p_i(encode_idx(i), encode_idx(l), &a_j_i);
                p_i.iter().enumerate().for_each(|(k, p)| {
                    G_k[k] += p * C_i;
                });
                i += 1;
            });
        if i < gens.max_set_size() {
            return Err(ProofError::SetIsTooSmall);
        } else if i > gens.max_set_size() {
            return Err(ProofError::SetIsTooLarge);
        }
        for k in 0..gens.n_bits - 1 {
            transcript.validate_and_append_point(b"G_k", &G_k[k].compress())?;
        }

        let (B, bit_proof, x) =
            gens.commit_bits(&mut transcript.clone(), encode_idx(l), &a_j_i[0])?;

        let z = r * scalar_exp(x, gens.n_bits) - Polynomial::from(rho_k).eval(x).unwrap();

        transcript.append_scalar(b"z", &z);

        Ok(OneOfManyProof {
            B,
            bit_proof,
            G_k,
            z,
        })
    }

    fn verify_batch_with_offsets(
        &self,
        gens: &ProofGens,
        transcript: &mut Transcript,
        proofs: &[OneOfManyProof],
        offsets: &[Option<&RistrettoPoint>],
    ) -> ProofResult<()> {
        transcript.one_of_many_proof_domain_sep(gens.n_bits as u64);

        // Every proof must have an entry in `offsets`, even if it is `None`.
        if proofs.len() != offsets.len() {
            return Err(ProofError::VerificationFailed);
        }

        let mut x_vec = Vec::new();
        for p in proofs {
            if !p.z.is_canonical() {
                return Err(ProofError::InvalidScalar(p.z));
            }

            let mut t = transcript.clone();
            for k in 0..gens.n_bits - 1 {
                t.validate_and_append_point(b"G_k", &p.G_k[k].compress())?;
            }
            x_vec.push(gens.verify_bits(&mut t, &p.B, &p.bit_proof)?);
        }

        // Batch verification strategy inspired by https://eprint.iacr.org/2019/373.pdf
        let mut set_size: usize = 0;
        let mut coeff_iters: Vec<SetCoefficientIterator> = proofs
            .iter()
            .zip(x_vec.iter())
            .map(|(p, x)| SetCoefficientIterator::from_f1_j_and_x(&p.bit_proof.f1_j, &x))
            .collect();
        let O = offsets
            .iter()
            .zip(coeff_iters.clone().iter_mut())
            .filter_map(|(O, coeff_iter)| {
                if let Some(O) = O {
                    Some((O, coeff_iter))
                } else {
                    None
                }
            })
            .map(|(&O, coeff_iter)| O * coeff_iter.sum::<Scalar>())
            .sum::<RistrettoPoint>();
        let C = self
            .clone()
            .map(|C_i| {
                set_size += 1;
                C_i * coeff_iters
                    .iter_mut()
                    .filter_map(|coeff_iter| coeff_iter.next())
                    .sum::<Scalar>()
            })
            .sum::<RistrettoPoint>();
        if set_size < gens.max_set_size() {
            return Err(ProofError::SetIsTooSmall);
        } else if set_size > gens.max_set_size() {
            return Err(ProofError::SetIsTooLarge);
        }
        let E = gens.commit(&Scalar::zero(), &proofs.iter().map(|p| p.z).sum())?;
        let G = proofs
            .iter()
            .zip(x_vec.iter())
            .map(|(p, &x)| p.G_k.eval(x).unwrap())
            .sum::<RistrettoPoint>();
        if C.is_identity() || E.is_identity() || G.is_identity() {
            return Err(ProofError::VerificationFailed);
        }
        if C != E + G + O {
            return Err(ProofError::VerificationFailed);
        }

        Ok(())
    }
}

trait VectorCommit {
    fn commit(self, gens: &ProofGens, r: &Scalar) -> ProofResult<RistrettoPoint>;
}

impl<I, T> VectorCommit for I
where
    I: Iterator<Item = T>,
    T: Mul<RistrettoPoint, Output = RistrettoPoint>,
{
    fn commit(self, gens: &ProofGens, r: &Scalar) -> ProofResult<RistrettoPoint> {
        let mut c = r * gens.G;
        for (i, v) in self.enumerate() {
            if i >= gens.H.len() {
                return Err(ProofError::SetIsTooLarge);
            }
            c += v * gens.H[i];
        }
        Ok(c)
    }
}

// Iterate over each coefficient according to optimized Gray code permutations of each previous
// coefficient.
#[derive(Clone)]
struct SetCoefficientIterator {
    f0_j: Vec<Scalar>,
    f0_inv_j: Vec<Scalar>,
    f1_j: Vec<Scalar>,
    f1_inv_j: Vec<Scalar>,
    n: usize,
    max_n: usize,
    nth_code: usize,
    nth_coeff: Scalar,
}

impl SetCoefficientIterator {
    fn from_f1_j_and_x(f1_j: &Vec<Scalar>, x: &Scalar) -> SetCoefficientIterator {
        let f1_j = f1_j.clone();
        let f0_j: Vec<Scalar> = f1_j.iter().map(|f1| x - f1).collect();
        let mut f1_inv_j = Vec::new();
        let mut f0_inv_j = Vec::new();
        // HACK -- We only need to compute the f tensor inversions if we intend to use them in
        // iterative Gray code computation. Otherwise we should not perform this computation.
        unsafe {
            if ENABLE_GRAY_CODE {
                f1_inv_j = f1_j.clone();
                Scalar::batch_invert(&mut f1_inv_j[..]);
                f0_inv_j = f0_j.clone();
                Scalar::batch_invert(&mut f0_inv_j[..]);
            }
        }
        let n = 0;
        let max_n = 2usize.checked_pow(f1_j.len() as u32).unwrap();
        let nth_code = encode_idx(n);
        let nth_coeff = f0_j.iter().product();
        SetCoefficientIterator {
            f0_j,
            f0_inv_j,
            f1_j,
            f1_inv_j,
            n,
            max_n,
            nth_code,
            nth_coeff,
        }
    }
}

impl Iterator for SetCoefficientIterator {
    type Item = Scalar;

    #[inline]
    fn next(&mut self) -> Option<Scalar> {
        if self.n < self.max_n {
            let next_coeff = self.nth_coeff;
            self.n += 1;
            // HACK -- This iterator has been modified to optionally iterate over Gray coded
            // indices or the standard binary sequence of integers.
            unsafe {
                if ENABLE_GRAY_CODE {
                    if self.n < self.max_n {
                        let next_code = gray_code(self.n);
                        let j = (self.nth_code ^ next_code).trailing_zeros() as usize;
                        if self.nth_code > next_code {
                            self.nth_coeff *= self.f1_inv_j[j];
                            self.nth_coeff *= self.f0_j[j];
                        } else {
                            self.nth_coeff *= self.f0_inv_j[j];
                            self.nth_coeff *= self.f1_j[j];
                        }
                        self.nth_code = next_code;
                    }
                } else {
                    self.nth_coeff = self.f0_j.iter().zip(self.f1_j.iter())
                        .enumerate()
                        .map(|(j, (f0, f1))| if 1 == bit(self.n, j) { f1 } else { f0 })
                        .product::<Scalar>();
                }
            }
            Some(next_coeff)
        } else {
            None
        }
    }
}

pub fn set_enable_gray_code(b: bool) {
    unsafe {
        ENABLE_GRAY_CODE = b;
    }
}

fn encode_idx(l: usize) -> usize {
    unsafe {
        if ENABLE_GRAY_CODE {
            // Convert to gray encoding
            gray_code(l)
        } else {
            // Do not encode
            l
        }
    }
}

fn compute_p_i(i: usize, l: usize, a_j_i: &Vec<Vec<Scalar>>) -> Vec<Scalar> {
    assert!(a_j_i.len() == 2); // Must have two rows of random scalars
    assert!(a_j_i[0].len() == a_j_i[1].len()); // Make sure each row is the same length
    let n_bits = a_j_i[0].len();

    // Create polynomial vector
    let mut p = Polynomial::from(Vec::with_capacity(n_bits));
    p.push(Scalar::one());

    // Multiply each polynomial
    for j in 0..n_bits {
        let mut f = Polynomial::new();
        f.push(a_j_i[bit(i, j)][j]);
        if 0 != delta(bit(l, j), bit(i, j)) {
            f.push(Scalar::one());
        }
        p *= f;
    }

    // Resize the vector to be M bits wide
    let mut v: Vec<Scalar> = p.into();
    v.resize_with(n_bits, || Scalar::zero());
    v
}

fn scalar_exp(base: Scalar, exp: usize) -> Scalar {
    let mut res = Scalar::one();
    for _ in 0..exp {
        res *= base;
    }
    res
}

fn bit(v: usize, j: usize) -> usize {
    (v >> j) & 1
}

fn delta(a: usize, b: usize) -> usize {
    if a == b {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::*;
    use crate::proofs::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use rand::rngs::OsRng; // You should use a more secure RNG

    #[test]
    fn new_generators() {
        assert!(ProofGens::new(5).is_ok());
        assert_eq!(ProofGens::new(0).unwrap_err(), ProofError::SetIsTooSmall);
        assert_eq!(ProofGens::new(1).unwrap_err(), ProofError::SetIsTooSmall);
        assert!(ProofGens::new(32).is_ok());
        assert_eq!(ProofGens::new(33).unwrap_err(), ProofError::SetIsTooLarge);
        assert_eq!(
            ProofGens::new(0xffffffff).unwrap_err(),
            ProofError::SetIsTooLarge
        );
    }

    #[test]
    fn gens_set_size() {
        // Not a lot can go wrong here, but test some corner cases to catch
        // potential issues between architectures

        // 8 bit corners
        let gens = ProofGens::new(7).unwrap();
        assert_eq!(gens.max_set_size(), 128);
        let gens = ProofGens::new(8).unwrap();
        assert_eq!(gens.max_set_size(), 256);
        let gens = ProofGens::new(9).unwrap();
        assert_eq!(gens.max_set_size(), 512);

        // 16 bit corners
        let gens = ProofGens::new(15).unwrap();
        assert_eq!(gens.max_set_size(), 32768);
        let gens = ProofGens::new(16).unwrap();
        assert_eq!(gens.max_set_size(), 65536);
        let gens = ProofGens::new(17).unwrap();
        assert_eq!(gens.max_set_size(), 131072);

        // 32 bit corners
        let gens = ProofGens::new(31).unwrap();
        assert_eq!(gens.max_set_size(), 2147483648);
        let gens = ProofGens::new(32).unwrap();
        assert_eq!(gens.max_set_size(), 4294967296);
        assert!(ProofGens::new(33).is_err());
    }

    #[test]
    fn bit_commitments() {
        // Set up proof generators
        let gens = ProofGens::new(5).unwrap();

        // Create the prover's commitment to zero
        let l: usize = 3; // The prover's commitment will be third in the set
        let t = Transcript::new(b"OneOfMany-Test");

        let a_j = (0..gens.n_bits)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<Scalar>>();

        // Compute a bit commitment and its proof
        let (B, proof, _) = gens.commit_bits(&mut t.clone(), l, &a_j).unwrap();
        assert!(gens.verify_bits(&mut t.clone(), &B, &proof).is_ok());

        // Check error if index out of bounds
        assert_eq!(
            gens.commit_bits(&mut t.clone(), gens.max_set_size(), &a_j)
                .unwrap_err(),
            ProofError::IndexOutOfBounds
        );
    }

    #[test]
    fn prove_single() {
        // Set up proof generators
        let gens = ProofGens::new(5).unwrap();

        // Create the prover's commitment to zero
        let l: usize = 3; // The prover's commitment will be third in the set
        let v = Scalar::zero();
        let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let C_l = gens.commit(&v, &r).unwrap();

        // Build a random set containing the prover's commitment at index `l`
        let mut set = (1..gens.max_set_size())
            .map(|_| RistrettoPoint::random(&mut OsRng))
            .collect::<Vec<RistrettoPoint>>();
        set.insert(l, C_l);
        let t = Transcript::new(b"OneOfMany-Test");

        // Compute a `OneOfMany` membership proof for this commitment
        let proof = set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap();
        assert!(set.iter().verify(&gens, &mut t.clone(), &proof).is_ok());

        // Check error if index out of bounds
        assert_eq!(
            set.iter()
                .prove(&gens, &mut t.clone(), gens.max_set_size(), &r)
                .unwrap_err(),
            ProofError::IndexOutOfBounds
        );

        // Prove should fail if set too small or too large
        let removed = set.pop().unwrap();
        assert_eq!(
            set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap_err(),
            ProofError::SetIsTooSmall
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert!(set.iter().prove(&gens, &mut t.clone(), l, &r).is_ok()); // Ok!
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap_err(),
            ProofError::SetIsTooLarge
        );

        // Return set to original state
        set.pop();
        set.pop();
        set.push(removed);

        // Verify should fail if set has been modified
        let removed = set.pop().unwrap();
        assert_eq!(
            set.iter()
                .verify(&gens, &mut t.clone(), &proof)
                .unwrap_err(),
            ProofError::SetIsTooSmall
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter()
                .verify(&gens, &mut t.clone(), &proof)
                .unwrap_err(),
            ProofError::VerificationFailed
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter()
                .verify(&gens, &mut t.clone(), &proof)
                .unwrap_err(),
            ProofError::SetIsTooLarge
        );

        // Return set to original state
        set.pop();
        set.pop();
        set.push(removed);
    }

    #[test]
    fn prove_single_with_offset() {
        // Set up proof generators
        let gens = ProofGens::new(5).unwrap();

        // Create the prover's commitment to zero
        let l: usize = 3; // The prover's commitment will be third in the set
        let v = Scalar::zero();
        let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let C_l = gens.commit(&v, &r).unwrap();

        // Build a random set containing the prover's commitment at index `l`
        let mut set = (1..gens.max_set_size())
            .map(|_| RistrettoPoint::random(&mut OsRng))
            .collect::<Vec<RistrettoPoint>>();
        set.insert(l, C_l);

        let t = Transcript::new(b"OneOfMany-Test");

        // First test with no offest
        let proof = set
            .iter()
            .prove_with_offset(&gens, &mut t.clone(), l, &r, None)
            .unwrap();
        assert!(set
            .iter()
            .verify_with_offset(&gens, &mut t.clone(), &proof, None)
            .is_ok());

        // Now replace C_l with a committment to a non-zero value
        let v = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let C_l = gens.commit(&v, &r).unwrap();
        set[l] = C_l;

        // Compute new commitment, to same value as `C_l`
        let r_new = Scalar::random(&mut OsRng);
        let C_new = gens.commit(&v, &r_new).unwrap(); // New commitment to same value

        // Now test with the valid offset and commitment to non-zero
        let proof = set
            .iter()
            .prove_with_offset(&gens, &mut t.clone(), l, &(r - r_new), Some(&C_new))
            .unwrap();
        assert!(set
            .iter()
            .verify_with_offset(&gens, &mut t.clone(), &proof, Some(&C_new))
            .is_ok());

        // Now test with the incorrect offset
        assert_eq!(
            set.iter()
                .verify_with_offset(
                    &gens,
                    &mut t.clone(),
                    &proof,
                    Some(&RistrettoPoint::random(&mut OsRng))
                )
                .unwrap_err(),
            ProofError::VerificationFailed
        );

        // Check error if index out of bounds
        assert_eq!(
            set.iter()
                .prove_with_offset(&gens, &mut t.clone(), gens.max_set_size(), &r, Some(&C_new))
                .unwrap_err(),
            ProofError::IndexOutOfBounds
        );

        // Prove should fail if set too small or too large
        let removed = set.pop().unwrap();
        assert_eq!(
            set.iter()
                .prove_with_offset(&gens, &mut t.clone(), l, &r, Some(&C_new))
                .unwrap_err(),
            ProofError::SetIsTooSmall
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert!(set
            .iter()
            .prove_with_offset(&gens, &mut t.clone(), l, &r, Some(&C_new))
            .is_ok()); // Ok!
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter()
                .prove_with_offset(&gens, &mut t.clone(), l, &r, Some(&C_new))
                .unwrap_err(),
            ProofError::SetIsTooLarge
        );

        // Return set to original state
        set.pop();
        set.pop();
        set.push(removed);

        // Verify should fail if set has been modified
        let removed = set.pop().unwrap();
        assert_eq!(
            set.iter()
                .verify_with_offset(&gens, &mut t.clone(), &proof, Some(&C_new))
                .unwrap_err(),
            ProofError::SetIsTooSmall
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter()
                .verify_with_offset(&gens, &mut t.clone(), &proof, Some(&C_new))
                .unwrap_err(),
            ProofError::VerificationFailed
        );
        set.push(RistrettoPoint::random(&mut OsRng));
        assert_eq!(
            set.iter()
                .verify_with_offset(&gens, &mut t.clone(), &proof, Some(&C_new))
                .unwrap_err(),
            ProofError::SetIsTooLarge
        );

        // Return set to original state
        set.pop();
        set.pop();
        set.push(removed);
    }

    #[test]
    fn prove_batch() {
        // Set up proof generators
        let gens = ProofGens::new(5).unwrap();

        // Create the prover's commitment to zero
        let l: usize = 3; // The prover's commitment will be third in the set
        let v = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let C_l = gens.commit(&v, &r).unwrap();

        // Compute new commitment, to same value as `C_l`
        let r_new = Scalar::random(&mut OsRng);
        let C_new = gens.commit(&v, &r_new).unwrap(); // New commitment to same value

        // Build a random set containing the prover's commitment at index `l`
        let mut set = (1..gens.max_set_size())
            .map(|_| RistrettoPoint::random(&mut OsRng))
            .collect::<Vec<RistrettoPoint>>();
        set.insert(l, C_l);

        let t = Transcript::new(b"OneOfMany-Test");

        // Verify batch with offsets
        let mut proofs = Vec::new();
        let mut offsets = Vec::new();
        for _ in 0..10 {
            proofs.push(
                set.iter()
                    .prove_with_offset(&gens, &mut t.clone(), l, &(r - r_new), Some(&C_new))
                    .unwrap(),
            );
            offsets.push(Some(&C_new));
        }
        assert!(set
            .iter()
            .verify_batch_with_offsets(&gens, &mut t.clone(), &proofs, &offsets)
            .is_ok());

        // Now replace C_l with a committment to zero
        let v = Scalar::zero();
        let C_l = gens.commit(&v, &r).unwrap();
        set[l] = C_l;

        // Now verify batch without offsets
        let mut proofs = Vec::new();
        for _ in 0..10 {
            proofs.push(set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap());
        }
        assert!(set
            .iter()
            .verify_batch(&gens, &mut t.clone(), &proofs)
            .is_ok());
    }

    #[test]
    fn serde() {
        // Set up proof generators
        let gens = ProofGens::new(5).unwrap();

        // Create the prover's commitment to zero
        let l: usize = 3; // The prover's commitment will be third in the set
        let v = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let r = Scalar::random(&mut OsRng); // You should use a more secure RNG
        let C_l = gens.commit(&v, &r).unwrap();

        // Compute new commitment, to same value as `C_l`
        let r_new = Scalar::random(&mut OsRng);
        let C_new = gens.commit(&v, &r_new).unwrap(); // New commitment to same value

        // Build a random set containing the prover's commitment at index `l`
        let mut set = (1..gens.max_set_size())
            .map(|_| RistrettoPoint::random(&mut OsRng))
            .collect::<Vec<RistrettoPoint>>();
        set.insert(l, C_l);

        let t = Transcript::new(b"OneOfMany-Test");

        // Verify batch with offsets
        let mut proofs = Vec::new();
        let mut offsets = Vec::new();
        for _ in 0..10 {
            proofs.push(
                set.iter()
                    .prove_with_offset(&gens, &mut t.clone(), l, &(r - r_new), Some(&C_new))
                    .unwrap(),
            );
            offsets.push(Some(&C_new));
        }
        let serialized = serde_cbor::to_vec(&proofs).unwrap();
        let proofs: Vec<OneOfManyProof> = serde_cbor::from_slice(&serialized[..]).unwrap();
        assert!(set
            .iter()
            .verify_batch_with_offsets(&gens, &mut t.clone(), &proofs, &offsets)
            .is_ok());

        // Now replace C_l with a committment to zero
        let v = Scalar::zero();
        let C_l = gens.commit(&v, &r).unwrap();
        set[l] = C_l;

        // Now verify batch without offsets
        let mut proofs = Vec::new();
        for _ in 0..10 {
            proofs.push(set.iter().prove(&gens, &mut t.clone(), l, &r).unwrap());
        }
        let serialized = serde_cbor::to_vec(&proofs).unwrap();
        let proofs: Vec<OneOfManyProof> = serde_cbor::from_slice(&serialized[..]).unwrap();
        assert!(set
            .iter()
            .verify_batch(&gens, &mut t.clone(), &proofs)
            .is_ok());
    }
}
