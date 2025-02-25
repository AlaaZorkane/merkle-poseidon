use ark_bn254::Fr;

use crate::{Hasher, InnerHash, MerklePath, PoseidonMerkleError, Sibling, SparseMerkleTree};

#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The siblings of the proof
    pub siblings: Vec<Sibling>,
    /// The path of the proof
    pub merkle_path: MerklePath,
    /// The leaf value of the proof
    pub leaf_value: Fr,
    /// The root hash of the proof
    pub root_hash: InnerHash,
}

impl MerkleProof {
    pub fn new(
        siblings: Vec<Sibling>,
        merkle_path: MerklePath,
        leaf_value: Fr,
        root_hash: InnerHash,
    ) -> Self {
        Self {
            siblings,
            merkle_path,

            leaf_value,
            root_hash,
        }
    }

    /// Verify the proof bottom up
    pub fn verify_proof(&self, hasher: &mut Hasher) -> Result<bool, PoseidonMerkleError> {
        // Start with the leaf value
        let mut current_hash = self.leaf_value;

        // Traverse the path from bottom to top
        // We need to iterate in reverse order (from leaf to root)
        // but keep the correct path bit positions
        let siblings_len = self.siblings.len();
        for (idx, sibling) in self.siblings.iter().rev().enumerate() {
            let position = siblings_len - idx - 1;
            let go_right = SparseMerkleTree::get_path_bit(&self.merkle_path, position);
            let (left, right) = if go_right {
                (*sibling, current_hash)
            } else {
                (current_hash, *sibling)
            };

            current_hash = hasher.hash(&[left, right])?;
            println!(
                "current_hash: ({:?}, {:?}) = {:?}",
                left, right, current_hash
            );
        }

        Ok(current_hash == self.root_hash)
    }
}
