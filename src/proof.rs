use ark_bn254::Fr;
use ark_ff::AdditiveGroup;

use crate::{Hasher, NodeHash, PathHash, PoseidonMerkleError, SparseMerkleTree};

#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The siblings of the proof
    pub siblings: Vec<NodeHash>,
    /// The path of the proof
    pub path: PathHash,
    /// The leaf value of the proof
    pub leaf_value: Fr,
    /// The root hash of the proof
    pub root_hash: NodeHash,
}

impl MerkleProof {
    pub fn new(
        siblings: Vec<NodeHash>,
        path: PathHash,
        leaf_value: Fr,
        root_hash: NodeHash,
    ) -> Self {
        Self {
            siblings,
            path,
            leaf_value,
            root_hash,
        }
    }

    /// Verify the proof bottom up
    pub fn verify_proof(&self, hasher: &mut Hasher) -> Result<bool, PoseidonMerkleError> {
        let mut current_hash = hasher.hash(&[self.leaf_value, Fr::ZERO])?;

        for (i, sibling) in self.siblings.iter().enumerate() {
            let go_right = SparseMerkleTree::get_path_bit(&self.path, i);
            let (left, right) = if go_right {
                (*sibling, current_hash)
            } else {
                (current_hash, *sibling)
            };

            current_hash = hasher.hash(&[left, right])?;
        }

        Ok(current_hash == self.root_hash)
    }
}
