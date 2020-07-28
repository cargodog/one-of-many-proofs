use one_of_many_proofs::proofs::*;

extern crate rand;
use rand::rngs::OsRng;

extern crate curve25519_dalek;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let l: usize = 1; // Index within the set, of the prover's commitment
    let v = Scalar::zero(); // Must prove commitment to zero
    let r = Scalar::random(&mut OsRng); // Blinding factor for prover's commitment

    let gens = ProofGens::new(6).unwrap(); // Set generators
    let C_l = gens.commit(&v, &r).unwrap(); // Prover's commitment

    // Build a random set containing the prover's commitment at index `l`
    let mut set = (1..gens.max_set_size())
        .map(|_| RistrettoPoint::random(&mut OsRng))
        .collect::<Vec<RistrettoPoint>>();
    set.insert(l, C_l);

    // Compute new commitment, to same value as `C_l`
    let r_new = Scalar::random(&mut OsRng);
    let C_new = gens.commit(&v, &r_new).unwrap(); // New commitment to same value

    let mut prover_transcript = Transcript::new(b"doctest example");
    let mut proofs = Vec::new();
    let mut offsets = Vec::new();
    for _ in 0..40 {
        let mut tscpt = prover_transcript.clone();
        proofs.push(
            set.iter()
                .prove_with_offset(&gens, &mut tscpt, l, &(r - r_new), Some(&C_new))
                .unwrap(),
        );
        offsets.push(Some(&C_new));
    }

    let mut verifier_transcript = Transcript::new(b"doctest example");
    c.bench_function("Manual verify 20", |b| {
        b.iter(|| {
            for (p, &o) in proofs[..20].iter().zip(offsets.iter()) {
                let mut t = verifier_transcript.clone();
                assert!(set
                    .iter()
                    .verify_with_offset(
                        black_box(&gens),
                        black_box(&mut t),
                        black_box(p),
                        black_box(o)
                    )
                    .is_ok());
            }
        })
    });

    let mut verifier_transcript = Transcript::new(b"doctest example");
    c.bench_function("Batch verify 20", |b| {
        b.iter(|| {
            let mut t = verifier_transcript.clone();
            assert!(set
                .iter()
                .verify_batch_with_offsets(
                    black_box(&gens),
                    black_box(&mut t),
                    black_box(&proofs[..20]),
                    black_box(offsets.as_slice())
                )
                .is_ok());
        })
    });

    let mut verifier_transcript = Transcript::new(b"doctest example");
    c.bench_function("Batch verify 40", |b| {
        b.iter(|| {
            let mut t = verifier_transcript.clone();
            assert!(set
                .iter()
                .verify_batch_with_offsets(
                    black_box(&gens),
                    black_box(&mut t),
                    black_box(&proofs[..40]),
                    black_box(offsets.as_slice())
                )
                .is_ok());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
