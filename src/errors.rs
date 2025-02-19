use light_poseidon::PoseidonError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum PoseidonMerkleError {
    #[error("depth size should be greater than 0")]
    InvalidDepth,
    #[error("poseidon hasher error: {0}")]
    HasherError(#[from] PoseidonError),
    #[error("invalid node type")]
    InvalidNodeType,
    #[error("invalid bits for path hash")]
    InvalidBitsPathHash,
    #[error("proof error: {0}")]
    SiblingNotFound(#[from] ProofError),
}

#[derive(Error, Debug, PartialEq)]
pub enum ProofError {
    #[error("sibling at position {0} not found to generate proof")]
    SiblingNotFound(usize),
}
