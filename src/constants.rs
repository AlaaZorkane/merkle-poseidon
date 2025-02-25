use ark_bn254::{Fr, FrConfig};
use ark_ff::{Fp, MontBackend};
use std::{str::FromStr, sync::OnceLock};

const EMPTY_LEAF_HASH_BN: &str =
    "19014214495641488759237505126948346942972912379615652741039992445865937985820";

const EMPTY_INNER_HASH_BN: &str =
    "10447686833432518214645507207530993719569269870494442919228205482093666444588";

static EMPTY_LEAF_HASH: OnceLock<Fp<MontBackend<FrConfig, 4>, 4>> = OnceLock::new();

/// Pre-computed poseidon(0) to mimic an empty leaf node
pub fn get_empty_leaf_hash() -> &'static Fp<MontBackend<FrConfig, 4>, 4> {
    EMPTY_LEAF_HASH.get_or_init(|| Fr::from_str(EMPTY_LEAF_HASH_BN).unwrap())
}

static EMPTY_INNER_HASH: OnceLock<Fp<MontBackend<FrConfig, 4>, 4>> = OnceLock::new();

/// Pre-computed poseidon(0, 0) to mimic an empty inner node
pub fn get_empty_inner_hash() -> &'static Fp<MontBackend<FrConfig, 4>, 4> {
    EMPTY_INNER_HASH.get_or_init(|| Fr::from_str(EMPTY_INNER_HASH_BN).unwrap())
}
