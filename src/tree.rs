use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::{
    get_empty_inner_hash,
    node::{InnerHash, Node},
    MerkleProof, NodeType, PoseidonMerkleError, ProofError,
};

/// A path in the merkle tree as a field element
///
/// The path corresponds to the bits of the field element (Fr::into_bigint().to_bits_le())
pub type MerklePath = Fr;

pub type Sibling = Fr;

/// Sparse Poseidon Merkle Tree
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<H: PoseidonHasher<Fr>> {
    /// The hasher for the tree
    hasher: H,
    /// The root of the tree
    pub root: Rc<RefCell<Node<H>>>,
    /// The MAX depth of the tree
    pub depth: usize,
}

impl SparseMerkleTree<Poseidon<Fr>> {
    /// Create a new (lazy) sparse poseidon merkle tree given a depth
    pub fn new(depth: usize) -> Result<Self, PoseidonMerkleError> {
        let poseidon = Poseidon::<Fr>::new_circom(2)?;
        Self::new_with_hasher(depth, poseidon)
    }

    /// Get the bit at the given position
    ///
    /// [true, false] -> [1, 0]
    pub fn get_path_bit(merkle_path: &MerklePath, position: usize) -> bool {
        let bits = merkle_path.into_bigint().to_bits_le();
        bits[position]
    }

    /// Get the root hash of the tree
    pub fn get_root_hash(&self) -> Result<InnerHash, PoseidonMerkleError> {
        let root = self.root.borrow();
        let hash = root.node_type.hash();

        match hash {
            Some(hash) => Ok(*hash),
            None => Err(PoseidonMerkleError::InvalidNodeType),
        }
    }

    /// Get the inner node at a given path and level
    ///
    /// root = level 0
    ///
    /// leaf = level depth
    pub fn get_inner_node(
        &self,
        merkle_path: &MerklePath,
        level: usize,
    ) -> Result<Rc<RefCell<Node<Poseidon<Fr>>>>, PoseidonMerkleError> {
        if level >= self.depth {
            return Err(PoseidonMerkleError::InvalidLevel);
        }

        let mut current = self.root.clone();
        for i in 0..level {
            let next = {
                let current_ref = current.borrow();
                let go_right = Self::get_path_bit(merkle_path, i);

                if go_right {
                    match &current_ref.right {
                        Some(node) => node.clone(),
                        None => Node::new_borrowed_empty_inner(),
                    }
                } else {
                    match &current_ref.left {
                        Some(node) => node.clone(),
                        None => Node::new_borrowed_empty_inner(),
                    }
                }
            };

            current = next.clone();
        }

        Ok(current)
    }

    /// Get the leaf node at a given path
    pub fn get_node(
        &self,
        merkle_path: &MerklePath,
    ) -> Result<Rc<RefCell<Node<Poseidon<Fr>>>>, PoseidonMerkleError> {
        let mut current = self.root.clone();
        for i in 0..self.depth {
            let next = {
                let current_ref = current.borrow();
                let go_right = Self::get_path_bit(merkle_path, i);

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

    /// Generate a proof for a given path, if through the path we meet an empty node, we return an error
    ///
    /// The path MUST BE valid for a NON-EMPTY value.
    pub fn generate_proof(
        &self,
        merkle_path: &MerklePath,
    ) -> Result<MerkleProof, PoseidonMerkleError> {
        let current = self.get_node(merkle_path)?;
        let current_ref = current.borrow();

        if let NodeType::Leaf(value) = current_ref.node_type {
            // Store siblings in the order they will be used during verification
            let mut siblings: Vec<Sibling> = Vec::with_capacity(self.depth);

            // First compute the leaf value hash
            let mut current = self.root.clone();

            // Collect siblings along the path
            for i in 0..self.depth {
                // If we're at the last node, we need to get the leaf sibling, which could be empty
                let is_last_node = i == self.depth - 1;
                let go_right = Self::get_path_bit(merkle_path, i);

                let next = {
                    let current_ref = current.borrow();

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

                // On last node, sibling is a leaf, default to empty value (Fr::ZERO)
                let sibling: Sibling = if go_right {
                    match &current_ref.left {
                        Some(node) => match &node.borrow().node_type {
                            NodeType::Leaf(_) => Err(ProofError::InnerNodeExpected),
                            NodeType::Inner(hash) => Ok(*hash),
                        },
                        None => {
                            if is_last_node {
                                Ok(Fr::ZERO)
                            } else {
                                Ok(*get_empty_inner_hash())
                            }
                        }
                    }?
                } else {
                    match &current_ref.right {
                        Some(node) => match &node.borrow().node_type {
                            NodeType::Leaf(_) => Err(ProofError::InnerNodeExpected),
                            NodeType::Inner(hash) => Ok(*hash),
                        },
                        None => {
                            if is_last_node {
                                Ok(Fr::ZERO)
                            } else {
                                Ok(*get_empty_inner_hash())
                            }
                        }
                    }?
                };

                siblings.push(sibling);
                current = next.clone();
            }

            let root_hash = self.get_root_hash()?;

            Ok(MerkleProof::new(siblings, *merkle_path, value, root_hash))
        } else {
            Err(PoseidonMerkleError::InvalidNodeType)
        }
    }

    /// Get the raw value at a given path for a valid leaf node
    pub fn get_value(&self, merkle_path: &MerklePath) -> Result<Fr, PoseidonMerkleError> {
        let node = self.get_node(merkle_path)?;
        let node_ref = node.borrow();
        if let NodeType::Leaf(value) = node_ref.node_type {
            Ok(value)
        } else {
            Err(PoseidonMerkleError::InvalidNodeType)
        }
    }

    /// Create a new sparse poseidon merkle tree given a depth
    pub fn new_with_hasher(
        depth: usize,
        hasher: Poseidon<Fr>,
    ) -> Result<SparseMerkleTree<Poseidon<Fr>>, PoseidonMerkleError> {
        if depth == 0 {
            return Err(PoseidonMerkleError::InvalidDepth);
        }

        Ok(SparseMerkleTree {
            hasher,
            root: Node::new_borrowed_empty_inner(),
            depth,
        })
    }

    /// Get the root hash of the tree
    pub fn root_hash(&mut self) -> Result<InnerHash, PoseidonMerkleError> {
        self.root.borrow().compute_hash(&mut self.hasher)
    }

    /// Insert a value at a given path
    pub fn insert_at_path(
        &mut self,
        merkle_path: &MerklePath,
        value: &Fr,
    ) -> Result<(), PoseidonMerkleError> {
        let mut backtrack_to_root: Vec<Rc<RefCell<Node<Poseidon<Fr>>>>> = Vec::new();

        // New closure to avoid borrowing issues
        {
            let mut current = self.root.clone();
            for i in 0..self.depth {
                let go_right = SparseMerkleTree::get_path_bit(merkle_path, i);
                let next = {
                    let mut current_ref = current.borrow_mut();
                    if go_right {
                        if current_ref.right.is_none() {
                            current_ref.right = Some(Node::new_borrowed_empty_inner());
                        }
                        current_ref.right.as_ref().unwrap().clone()
                    } else {
                        if current_ref.left.is_none() {
                            current_ref.left = Some(Node::new_borrowed_empty_inner());
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
        }

        // Recalculate hashes bottom-up
        let rev_backtrack_to_root = backtrack_to_root.iter().rev();
        for node in rev_backtrack_to_root {
            node.borrow_mut().recalculate_hash(&mut self.hasher)?;
        }

        Ok(())
    }

    /// Delete a value at a given path by inserting a zero value at given path
    pub fn delete_at_path(&mut self, merkle_path: &MerklePath) -> Result<(), PoseidonMerkleError> {
        let zero = Fr::ZERO;
        self.insert_at_path(merkle_path, &zero)?;

        Ok(())
    }

    /// Get the path hash from a list of bits
    pub fn get_merkle_path(&self, path: &[bool]) -> Result<MerklePath, PoseidonMerkleError> {
        let path_bits = BigInt::from_bits_le(path);
        let merkle_path =
            Fr::from_bigint(path_bits).ok_or(PoseidonMerkleError::InvalidBitsPathHash)?;
        Ok(merkle_path)
    }

    /// Check if the tree is empty lazily o(1)
    pub fn is_empty(&self) -> bool {
        let root = self.root.borrow();
        let empty_hash = get_empty_inner_hash();

        root.node_type.hash().unwrap_or(empty_hash).eq(empty_hash)
    }

    /// Clear the tree by resetting the root to a new empty node
    ///
    /// Since we're using RC, children will be automatically cleared
    pub fn clear(&mut self) {
        self.root = Node::new_borrowed_empty_inner();
    }
}

impl Default for SparseMerkleTree<Poseidon<Fr>> {
    fn default() -> Self {
        let poseidon =
            Poseidon::<Fr>::new_circom(2).expect("Failed to create default Poseidon hasher");
        Self::new_with_hasher(20, poseidon).expect("Failed to create default SparseMerkleTree")
    }
}
