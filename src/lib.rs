//! Zero knowledge membership proofs based on the
//! [One-out-of-Many](https://eprint.iacr.org/2014/764) proof scheme.
//!
//! This membership proofs allow you to prove knowledge of the opening of a
//! pedersen commitment, within a set of pedersen commitments, without
//! revealing anything about the commitment or its position within the set.
//!
//! # Examples
//! Prove you know a commitment to zero, `C_l`, within a set of commitments:
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
//! Prove you know a commitment that opens to any value (possibly non-zero),
//! within a set of commitments:
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
//! let v = Scalar::random(&mut OsRng); // Commit to any random value
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
//!
//! # Perfomance
//! The proof(s) provided by this crate depend heavily on the
//! [curve25519-dalek](https://docs.rs/curve25519-dalek) for elliptic curve operations on the
//! ristretto255 curve group. These operations can be optimized by compiling to use the SIMD
//! backend. To do set this compile option, set the following environment variable:
//! ```bash
//! export RUSTFLAGS="-C target_cpu=native"
//! ```
//!
//! Benchmarks are run using [criterion.rs](https://docs.rs/criterion):
//! ```bash
//! cargo bench
//! ```
//!
//! # References
//! * [One-out-of-Many Proofs: Or How to Leak a Secret and Spend a Coin](https://eprint.iacr.org/2014/764)
//! * [Short Accountable Ring Signatures Based on DDH](https://eprint.iacr.org/2015/643)

#![no_std]
#![feature(test)]

//-----------------------------------------------------------------------------
// External dependencies:
//-----------------------------------------------------------------------------
extern crate curve25519_dalek;
extern crate polynomials;
extern crate sha3;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

//-----------------------------------------------------------------------------
// Public modules
//-----------------------------------------------------------------------------
pub mod errors;
pub mod proofs;

//-----------------------------------------------------------------------------
// Internal modules
//-----------------------------------------------------------------------------
pub(crate) mod transcript;
