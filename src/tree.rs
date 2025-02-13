use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonError, PoseidonHasher};

use crate::{
    node::{Node, NodeHash},
    PoseidonMerkleTreeError,
};

type PathHash = Fr;

/// Sparse Poseidon Merkle Tree
pub struct SparsePoseidonMerkleTree {
    /// The hash of the empty node
    empty_node_hash: NodeHash,
    /// The hasher for the tree (poseidon_circom_2)
    hasher: Box<dyn PoseidonHasher<Fr>>,
    /// The root of the tree
    root: Option<Box<Node>>,
    /// The MAX depth of the tree
    depth: usize,
}

impl SparsePoseidonMerkleTree {
    fn empty_node_hash() -> Result<NodeHash, PoseidonMerkleTreeError> {
        let mut empty_poseidon = Poseidon::<Fr>::new_circom(0)?;
        let hash = empty_poseidon.hash(&[])?;
        Ok(hash)
    }

    pub fn new(depth: usize) -> Result<Self, PoseidonMerkleTreeError> {
        if depth == 0 {
            return Err(PoseidonMerkleTreeError::InvalidDepth);
        }

        let poseidon = Poseidon::<Fr>::new_circom(2)?;
        Ok(SparsePoseidonMerkleTree {
            empty_node_hash: Self::empty_node_hash()?,
            hasher: Box::new(poseidon),
            root: Some(Box::new(Node::new_inner())),
            depth,
        })
    }

    pub fn root_hash(&mut self) -> Result<NodeHash, PoseidonError> {
        match &self.root {
            Some(node) => node.compute_hash(&mut self.hasher, &self.empty_node_hash),
            None => Ok(self.empty_node_hash),
        }
    }

    pub fn insert_at_path(
        &mut self,
        path_hash: &PathHash,
        value: &Fr,
    ) -> Result<(), PoseidonError> {
        todo!()
    }

    pub fn get_path_bit(&self, path_hash: &PathHash, position: usize) -> bool {
        let bytes = path_hash.into_bigint().to_bits_be();
        bytes[position]
    }
}
