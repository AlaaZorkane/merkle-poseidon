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
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<H: PoseidonHasher<Fr>> {
    /// Empty hash
    empty_hash: NodeHash,
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

    /// The hash of an empty node
    ///
    /// _We arent using lazy static here because it's wonky with wasm_
    pub fn empty_node_hash() -> Result<NodeHash, PoseidonMerkleError> {
        let zero = Fr::ZERO;
        let mut empty_poseidon = Poseidon::<Fr>::new_circom(1)?;
        let hash = empty_poseidon.hash(&[zero])?;
        Ok(hash)
    }

    /// Get the bit at the given position
    ///
    /// [true, false] -> [1, 0]
    pub fn get_path_bit(path_hash: &PathHash, position: usize) -> bool {
        let bits = path_hash.into_bigint().to_bits_le();
        bits[position]
    }

    /// Get the node at a given path
    pub fn get_node(
        &self,
        path_hash: &PathHash,
    ) -> Result<Rc<RefCell<Node<Poseidon<Fr>>>>, PoseidonMerkleError> {
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

    /// Generate a proof for a given path
    pub fn generate_proof(&self, path_hash: &PathHash) -> Result<MerkleProof, PoseidonMerkleError> {
        let current = self.get_node(path_hash)?;
        let current_ref = current.borrow();

        if let NodeType::Leaf(value) = current_ref.node_type {
            let mut siblings: Vec<NodeHash> = Vec::new();

            let mut current = self.root.clone();
            for i in 0..self.depth - 1 {
                let go_right = Self::get_path_bit(path_hash, i);
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
                let sibling: NodeHash = if go_right {
                    // Left sibling hash
                    match &current_ref.left {
                        Some(node) => node.borrow().hash,
                        None => Some(self.empty_hash),
                    }
                    .ok_or(ProofError::SiblingNotFound(i))?
                } else {
                    match &current_ref.right {
                        Some(node) => node.borrow().hash,
                        None => Some(self.empty_hash),
                    }
                    .ok_or(ProofError::SiblingNotFound(i))?
                };

                siblings.push(sibling);
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
    /// Create a new (eager) sparse poseidon merkle tree given a depth
    pub fn new_eager(depth: usize) -> Result<SparseMerkleTree<Poseidon<Fr>>, PoseidonMerkleError> {
        todo!("new_eager depth: {}", depth);
    }

    /// Create a new (lazy) sparse poseidon merkle tree given a depth
    ///
    /// We arent creating any nodes here, if you want to create a tree with
    /// actual nodes, you should use the `new_eager` method
    pub fn new_with_hasher(
        depth: usize,
        hasher: Poseidon<Fr>,
    ) -> Result<SparseMerkleTree<Poseidon<Fr>>, PoseidonMerkleError> {
        if depth == 0 {
            return Err(PoseidonMerkleError::InvalidDepth);
        }

        Ok(SparseMerkleTree {
            empty_hash: SparseMerkleTree::empty_node_hash()?,
            hasher,
            root: Node::new_inner(),
            depth,
        })
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
        let mut backtrack_to_root: Vec<Rc<RefCell<Node<Poseidon<Fr>>>>> = Vec::new();

        // New closure to avoid borrowing issues
        {
            let mut current = self.root.clone();
            for i in 0..self.depth - 1 {
                let next = {
                    let mut current_ref = current.borrow_mut();
                    let go_right = SparseMerkleTree::get_path_bit(path_hash, i);

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
            backtrack_to_root.push(current.clone());
        }

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

    /// Get the path hash from a list of bits
    pub fn get_path_hash(&self, path: &[bool]) -> Result<PathHash, PoseidonMerkleError> {
        let path_bits = BigInt::from_bits_le(path);
        let path_hash =
            Fr::from_bigint(path_bits).ok_or(PoseidonMerkleError::InvalidBitsPathHash)?;
        Ok(path_hash)
    }

    /// Check if the tree is empty lazily o(1)
    pub fn is_empty(&self) -> bool {
        let root = self.root.borrow();
        root.hash.is_none() || root.hash == Some(self.empty_hash)
    }

    /// Clear the tree by resetting the root to a new empty node
    ///
    /// Since we're using RC, children will be automatically cleared
    pub fn clear(&mut self) -> Result<(), PoseidonError> {
        // Create a new empty root node
        self.root = Node::new_inner();

        // Reset the root hash to empty hash
        self.root.borrow_mut().hash = Some(self.empty_hash);

        Ok(())
    }
}

impl Default for SparseMerkleTree<Poseidon<Fr>> {
    fn default() -> Self {
        let poseidon =
            Poseidon::<Fr>::new_circom(2).expect("Failed to create default Poseidon hasher");
        Self::new_with_hasher(20, poseidon).expect("Failed to create default SparseMerkleTree")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    const DEPTH: usize = 4;
    const TEST_PATH: [bool; DEPTH - 1] = [true, false, true];

    /// Setup a new tree with a depth of 4 (for testing purposes)
    fn setup_tree() -> SparseMerkleTree<Poseidon<Fr>> {
        SparseMerkleTree::new(DEPTH).unwrap()
    }

    #[test]
    fn test_new_tree() {
        let tree = setup_tree();
        assert_eq!(tree.depth, 4);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_invalid_depth() {
        let result = SparseMerkleTree::new(0);
        assert!(matches!(result, Err(PoseidonMerkleError::InvalidDepth)));
    }

    #[test]
    fn test_empty_node_hash() {
        let hash = SparseMerkleTree::<Poseidon<Fr>>::empty_node_hash().unwrap();
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = setup_tree();
        let path_hash = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
        let value = Fr::from(123u64);

        // Insert value
        tree.insert_at_path(&path_hash, &value).unwrap();

        // Get and verify value
        let retrieved_value = tree.get_value(&path_hash).unwrap();
        assert_eq!(retrieved_value, value);
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_delete() {
        let mut tree = setup_tree();
        let path_hash = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
        let value = Fr::from(123u64);

        // Insert and then delete
        tree.insert_at_path(&path_hash, &value).unwrap();
        tree.delete_at_path(&path_hash).unwrap();

        // Verify value is zero
        let retrieved_value = tree.get_value(&path_hash).unwrap();
        assert_eq!(retrieved_value, Fr::zero());
    }

    #[test]
    fn test_clear() {
        let mut tree = setup_tree();
        let path_hash = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
        let value = Fr::from(123u64);

        tree.insert_at_path(&path_hash, &value).unwrap();
        tree.clear().unwrap();
        assert!(tree.is_empty());
    }

    #[test]
    fn test_path_bit_extraction() {
        let bi = BigInt::from_bits_le(&TEST_PATH);
        let path_hash = Fr::from_bigint(bi).unwrap();

        assert!(SparseMerkleTree::get_path_bit(&path_hash, 0)); // Should be 1
        assert!(!SparseMerkleTree::get_path_bit(&path_hash, 1)); // Should be 0
        assert!(SparseMerkleTree::get_path_bit(&path_hash, 2)); // Should be 1
        assert!(!SparseMerkleTree::get_path_bit(&path_hash, 3)); // Should be 0
    }

    #[test]
    fn test_get_path_hash() {
        let tree = setup_tree();
        let path = TEST_PATH;
        let path_hash = tree.get_path_hash(&path).unwrap();

        // Verify bits can be extracted back
        assert_eq!(SparseMerkleTree::get_path_bit(&path_hash, 0), path[0]);
        assert_eq!(SparseMerkleTree::get_path_bit(&path_hash, 1), path[1]);
        assert_eq!(SparseMerkleTree::get_path_bit(&path_hash, 2), path[2]);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = setup_tree();
        let path_hash = Fr::from_bigint(BigInt::from_bits_le(&TEST_PATH)).unwrap();
        let value = Fr::from(100u64);

        // Insert a value
        tree.insert_at_path(&path_hash, &value).unwrap();

        // Generate proof
        let proof = tree.generate_proof(&path_hash).unwrap();

        // Verify proof matches inserted data
        assert_eq!(proof.path, path_hash);
        assert_eq!(proof.leaf_value, value);

        // Verify proof cryptographically
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
        assert!(proof.verify_proof(&mut hasher).unwrap());
    }

    #[test]
    fn test_iterator() {
        let mut tree = setup_tree();
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

        // Insert some values
        let entries = [
            (
                Fr::from_bigint(BigInt::from_bits_le(&[false, false, false])).unwrap(),
                Fr::from(100u64),
            ),
            (
                Fr::from_bigint(BigInt::from_bits_le(&[false, false, true])).unwrap(),
                Fr::from(200u64),
            ),
            (
                Fr::from_bigint(BigInt::from_bits_le(&[true, true, false])).unwrap(),
                Fr::from(300u64),
            ),
            (
                Fr::from_bigint(BigInt::from_bits_le(&[true, true, true])).unwrap(),
                Fr::from(400u64),
            ),
        ];

        for (path, value) in entries.iter() {
            tree.insert_at_path(path, value).unwrap();
        }

        // Collect all entries from iterator
        let tree_iter = tree.iter();
        let found_entries: Vec<(PathHash, Fr)> = tree_iter.collect();

        // Verify all inserted entries are found in order
        for (i, (hash, value)) in found_entries.iter().enumerate() {
            let computed_hash = hasher.hash(&[entries[i].1, Fr::ZERO]).unwrap();
            assert_eq!(computed_hash, *hash);
            assert_eq!(entries[i].1, *value);
        }
    }

    #[test]
    fn test_default() {
        let tree = SparseMerkleTree::default();
        assert_eq!(tree.depth, 20);
        assert!(tree.is_empty());
    }
}
