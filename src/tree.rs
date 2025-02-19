use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonError, PoseidonHasher};

use crate::{
    node::{Node, NodeHash},
    MerkleProof, NodeType, PoseidonMerkleError, ProofError,
};

pub type PathHash = Fr;

/// Sparse Poseidon Merkle Tree
pub struct SparseMerkleTree {
    /// Empty hash
    empty_hash: NodeHash,
    /// The hasher for the tree (poseidon_circom_2)
    hasher: Box<dyn PoseidonHasher<Fr>>,
    /// The root of the tree
    root: Rc<RefCell<Node>>,
    /// The MAX depth of the tree
    depth: usize,
}

impl SparseMerkleTree {
    /// The hash of an empty node
    ///
    /// _We arent using lazy static here because it's wonky with wasm_
    fn empty_node_hash() -> Result<NodeHash, PoseidonMerkleError> {
        let zero = Fr::ZERO;
        let mut empty_poseidon = Poseidon::<Fr>::new_circom(1)?;
        let hash = empty_poseidon.hash(&[zero])?;
        Ok(hash)
    }

    /// Create a new (eager) sparse poseidon merkle tree given a depth
    pub fn new_eager(depth: usize) -> Result<Self, PoseidonMerkleError> {
        todo!("new_eager depth: {}", depth);
    }

    /// Create a new (lazy) sparse poseidon merkle tree given a depth
    ///
    /// We arent creating any nodes here, if you want to create a tree with
    /// actual nodes, you should use the `new_eager` method
    pub fn new(depth: usize) -> Result<Self, PoseidonMerkleError> {
        if depth == 0 {
            return Err(PoseidonMerkleError::InvalidDepth);
        }

        let poseidon = Poseidon::<Fr>::new_circom(2)?;
        Ok(SparseMerkleTree {
            empty_hash: Self::empty_node_hash()?,
            hasher: Box::new(poseidon),
            root: Node::new_inner(),
            depth,
        })
    }

    /// Get the node at a given path
    pub fn get_node(&self, path_hash: &PathHash) -> Result<Rc<RefCell<Node>>, PoseidonMerkleError> {
        let mut current = self.root.clone();
        for i in 0..self.depth - 1 {
            let next = {
                let current_ref = current.borrow();
                let go_right = Self::get_path_bit(path_hash, i);

                if go_right {
                    current_ref.right.as_ref().unwrap().clone()
                } else {
                    current_ref.left.as_ref().unwrap().clone()
                }
            };

            current = next.clone();
        }

        Ok(current)
    }

    /// Get the value at a given path
    pub fn get_value(&self, path_hash: &PathHash) -> Result<Fr, PoseidonMerkleError> {
        let node = self.get_node(path_hash)?;
        let node_ref = node.borrow();
        if let NodeType::Leaf(value) = node_ref.node_type {
            Ok(value)
        } else {
            Err(PoseidonMerkleError::InvalidNodeType)
        }
    }

    /// Get the root hash of the tree
    pub fn root_hash(&mut self) -> Result<NodeHash, PoseidonError> {
        self.root
            .borrow()
            .compute_hash(&mut self.hasher, &self.empty_hash)
    }

    /// Insert a value at a given path
    pub fn insert_at_path(
        &mut self,
        path_hash: &PathHash,
        value: &Fr,
    ) -> Result<(), PoseidonError> {
        let mut backtrack_to_root: Vec<Rc<RefCell<Node>>> = Vec::new();

        let mut current = self.root.clone();
        for i in 0..self.depth - 1 {
            let next = {
                let mut current_ref = current.borrow_mut();
                let go_right = Self::get_path_bit(path_hash, i);

                if go_right {
                    if current_ref.right.is_none() {
                        current_ref.right = Some(Node::new_inner());
                    }
                    current_ref.right.as_ref().unwrap().clone()
                } else {
                    if current_ref.left.is_none() {
                        current_ref.left = Some(Node::new_inner());
                    }
                    current_ref.left.as_ref().unwrap().clone()
                }
            };

            backtrack_to_root.push(current.clone());
            current = next.clone();
        }

        // At leaf level, we insert the value
        let mut current_ref = current.borrow_mut();
        *current_ref = Node::new_leaf(*value);

        // Recalculate hashes bottom-up
        let rev_backtrack_to_root = backtrack_to_root.iter().rev();
        for node in rev_backtrack_to_root {
            node.borrow_mut()
                .recalculate_hash(&mut self.hasher, &self.empty_hash)?;
        }

        Ok(())
    }

    /// Delete a value at a given path by inserting a zero value at given path
    pub fn delete_at_path(&mut self, path_hash: &PathHash) -> Result<(), PoseidonError> {
        let zero = Fr::ZERO;
        self.insert_at_path(path_hash, &zero)?;

        Ok(())
    }

    /// Get the bit at the given position
    ///
    /// [true, false] -> [1, 0]
    pub fn get_path_bit(path_hash: &PathHash, position: usize) -> bool {
        let bytes = path_hash.into_bigint().to_bits_be();
        bytes[position]
    }

    /// Get the path hash from a list of bits
    pub fn get_path_hash(&self, path: &[bool]) -> Result<PathHash, PoseidonMerkleError> {
        let path_bits = BigInt::from_bits_be(path);
        let path_hash =
            Fr::from_bigint(path_bits).ok_or(PoseidonMerkleError::InvalidBitsPathHash)?;
        Ok(path_hash)
    }

    /// Check if the tree is empty lazily o(1)
    pub fn is_empty(&self) -> bool {
        let root = self.root.borrow();
        root.hash.is_none() || root.hash == Some(self.empty_hash)
    }

    /// Generate a proof for a given path
    pub fn generate_proof(&self, path_hash: &PathHash) -> Result<MerkleProof, PoseidonMerkleError> {
        let current = self.get_node(path_hash)?;
        let current_ref = current.borrow();

        if let NodeType::Leaf(value) = current_ref.node_type {
            let mut siblings: Vec<NodeHash> = Vec::new();

            let mut current = current.clone();
            for i in 0..self.depth - 1 {
                let next = {
                    let current_ref = current.borrow();
                    let go_right = Self::get_path_bit(path_hash, i);

                    if go_right {
                        current_ref
                            .right
                            .as_ref()
                            .ok_or(ProofError::SiblingNotFound(i))?
                            .clone()
                    } else {
                        current_ref
                            .left
                            .as_ref()
                            .ok_or(ProofError::SiblingNotFound(i))?
                            .clone()
                    }
                };

                siblings.push(next.borrow().hash.unwrap());
                current = next.clone();
            }

            Ok(MerkleProof::new(
                siblings,
                *path_hash,
                value,
                self.root.borrow().hash.unwrap(),
            ))
        } else {
            Err(PoseidonMerkleError::InvalidNodeType)
        }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new(20).unwrap()
    }
}
