use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use light_poseidon::PoseidonHasher;

use crate::{get_empty_inner_hash, PoseidonMerkleError};

/// Poseidon(left, right)
pub type InnerHash = Fr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    /// A leaf node with a raw value (no hash) this is Fr::ZERO if the node is empty
    Leaf(Fr),
    /// An inner node with a hash
    Inner(InnerHash),
}

impl NodeType {
    /// Get the hash of an inner node, None if the node is a leaf node
    pub fn hash(&self) -> Option<&InnerHash> {
        match self {
            NodeType::Leaf(_) => None,
            NodeType::Inner(hash) => Some(hash),
        }
    }

    /// Get the value of a leaf node, None if the node is an inner node
    pub fn value(&self) -> Option<&Fr> {
        match self {
            NodeType::Leaf(value) => Some(value),
            NodeType::Inner(_) => None,
        }
    }

    /// Get either the value or the hash of the node
    pub fn data(&self) -> &Fr {
        match self {
            NodeType::Leaf(value) => value,
            NodeType::Inner(hash) => hash,
        }
    }
}

// TODO: add path hash, depth level and sibling hash
#[derive(Debug, Clone)]
pub struct Node<H: PoseidonHasher<Fr>> {
    pub node_type: NodeType,
    pub left: Option<Rc<RefCell<Node<H>>>>,
    pub right: Option<Rc<RefCell<Node<H>>>>,
}

impl<H: PoseidonHasher<Fr>> Node<H> {
    pub fn new_empty_leaf() -> Self {
        Node {
            node_type: NodeType::Leaf(Fr::ZERO),
            left: None,
            right: None,
        }
    }

    pub fn new_empty_inner() -> Self {
        Node {
            node_type: NodeType::Inner(*get_empty_inner_hash()),
            left: None,
            right: None,
        }
    }

    pub fn new_leaf(value: Fr) -> Self {
        Node {
            node_type: NodeType::Leaf(value),
            left: None,
            right: None,
        }
    }

    pub fn new_inner(hash: InnerHash) -> Self {
        Node {
            node_type: NodeType::Inner(hash),
            left: None,
            right: None,
        }
    }

    pub fn new_borrowed_inner(hash: InnerHash) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node::new_inner(hash)))
    }

    pub fn new_borrowed_leaf(value: Fr) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node::new_leaf(value)))
    }

    pub fn new_borrowed_empty_leaf() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node::new_empty_leaf()))
    }

    pub fn new_borrowed_empty_inner() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node::new_empty_inner()))
    }

    /// Check if the node is the last inner node (either left or right is a leaf)
    pub fn is_last_inner(&self) -> bool {
        let left_is_leaf = self
            .left
            .as_ref()
            .map(|node| matches!(node.borrow().node_type, NodeType::Leaf(_)))
            .unwrap_or(false);

        let right_is_leaf = self
            .right
            .as_ref()
            .map(|node| matches!(node.borrow().node_type, NodeType::Leaf(_)))
            .unwrap_or(false);

        left_is_leaf || right_is_leaf
    }

    /// Computes the hash of the node
    ///
    /// If it's an inner node, we first check if our left/right are inners or leaves
    /// If they are inners, we recursively compute their hash
    /// If they are leaves, we hash the raw values.
    pub fn compute_hash(&self, hasher: &mut H) -> Result<InnerHash, PoseidonMerkleError> {
        match &self.node_type {
            NodeType::Inner(_) => {
                let is_last_inner = self.is_last_inner();

                let left_hash_or_zero = self
                    .left
                    .as_ref()
                    .map(|node| node.borrow().compute_hash(hasher))
                    .transpose()?
                    .unwrap_or(if is_last_inner {
                        Fr::ZERO
                    } else {
                        *get_empty_inner_hash()
                    });

                let right_hash_or_zero = self
                    .right
                    .as_ref()
                    .map(|node| node.borrow().compute_hash(hasher))
                    .transpose()?
                    .unwrap_or(if is_last_inner {
                        Fr::ZERO
                    } else {
                        *get_empty_inner_hash()
                    });

                Ok(hasher.hash(&[left_hash_or_zero, right_hash_or_zero])?)
            }
            NodeType::Leaf(value) => {
                // For leaf nodes, we return the value
                Ok(*value)
            }
        }
    }

    /// Invalidate and recalculate the hash of the node
    pub fn recalculate_hash(&mut self, hasher: &mut H) -> Result<(), PoseidonMerkleError> {
        self.node_type = match &self.node_type {
            NodeType::Leaf(value) => NodeType::Leaf(*value),
            NodeType::Inner(_) => NodeType::Inner(self.compute_hash(hasher)?),
        };

        Ok(())
    }
}

impl<H: PoseidonHasher<Fr>> PartialEq for Node<H> {
    fn eq(&self, other: &Self) -> bool {
        self.node_type == other.node_type
    }
}

impl<H: PoseidonHasher<Fr>> Eq for Node<H> {}
