use ark_bn254::Fr;
use light_poseidon::PoseidonHasher;

pub type Hasher = dyn PoseidonHasher<Fr>;
