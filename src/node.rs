use std::{cell::RefCell, rc::Rc};

use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use light_poseidon::{PoseidonError, PoseidonHasher};

pub type NodeHash = Fr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    Leaf(Fr),
    Inner,
}

// TODO: add path hash, depth level and sibling hash
#[derive(Debug, Clone)]
pub struct Node<H: PoseidonHasher<Fr>> {
    pub node_type: NodeType,
    pub left: Option<Rc<RefCell<Node<H>>>>,
    pub right: Option<Rc<RefCell<Node<H>>>>,
    pub hash: Option<NodeHash>,
}

impl<H: PoseidonHasher<Fr>> Node<H> {
    pub fn new_leaf(value: Fr) -> Self {
        Node {
            node_type: NodeType::Leaf(value),
            left: None,
            right: None,
            hash: None,
        }
    }

    pub fn new_inner() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node {
            node_type: NodeType::Inner,
            left: None,
            right: None,
            hash: None,
        }))
    }

    pub fn compute_hash(
        &self,
        hasher: &mut H,
        empty_hash: &NodeHash,
    ) -> Result<NodeHash, PoseidonError> {
        if let Some(hash) = self.hash {
            return Ok(hash);
        }

        match &self.node_type {
            NodeType::Leaf(value) => hasher.hash(&[*value, Fr::ZERO]),
            NodeType::Inner => {
                let left_hash = self
                    .left
                    .as_ref()
                    .map(|node| node.borrow().compute_hash(hasher, empty_hash))
                    .transpose()?
                    .unwrap_or(*empty_hash);

                let right_hash = self
                    .right
                    .as_ref()
                    .map(|node| node.borrow().compute_hash(hasher, empty_hash))
                    .transpose()?
                    .unwrap_or(*empty_hash);

                hasher.hash(&[left_hash, right_hash])
            }
        }
    }

    /// Invalidate and recalculate the hash of the node
    pub fn recalculate_hash(
        &mut self,
        hasher: &mut H,
        empty_hash: &NodeHash,
    ) -> Result<(), PoseidonError> {
        self.hash = Some(self.compute_hash(hasher, empty_hash)?);

        Ok(())
    }
}

impl<H: PoseidonHasher<Fr>> PartialEq for Node<H> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<H: PoseidonHasher<Fr>> Eq for Node<H> {}
