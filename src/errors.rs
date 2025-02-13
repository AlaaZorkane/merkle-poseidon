use light_poseidon::PoseidonError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum PoseidonMerkleTreeError {
    #[error("depth size should be greater than 0")]
    InvalidDepth,
    #[error("poseidon hasher error: {0}")]
    HasherError(#[from] PoseidonError),
}
