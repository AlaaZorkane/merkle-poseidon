use ark_bn254::Fr;
use light_poseidon::{PoseidonError, PoseidonHasher};

pub type NodeHash = Fr;

pub enum NodeType {
    Leaf(Fr),
    Inner,
}

pub struct Node {
    node_type: NodeType,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    hash: Option<NodeHash>,
}

impl Node {
    pub fn new_leaf(value: Fr) -> Self {
        Node {
            node_type: NodeType::Leaf(value),
            left: None,
            right: None,
            hash: None,
        }
    }

    pub fn new_inner() -> Self {
        Node {
            node_type: NodeType::Inner,
            left: None,
            right: None,
            hash: None,
        }
    }

    pub fn compute_hash(
        &self,
        poseidon: &mut Box<dyn PoseidonHasher<Fr>>,
        empty_hash: &NodeHash,
    ) -> Result<NodeHash, PoseidonError> {
        if let Some(hash) = self.hash {
            return Ok(hash);
        }

        match &self.node_type {
            NodeType::Leaf(value) => Ok(*value),
            NodeType::Inner => {
                let left_hash = self
                    .left
                    .as_ref()
                    .map(|node| node.compute_hash(poseidon, empty_hash))
                    .transpose()?
                    .unwrap_or(*empty_hash);

                let right_hash = self
                    .right
                    .as_ref()
                    .map(|node| node.compute_hash(poseidon, empty_hash))
                    .transpose()?
                    .unwrap_or(*empty_hash);

                poseidon.hash(&[left_hash, right_hash])
            }
        }
    }

    /// Clears the hash of the node and all its children
    pub fn clear_hash(&mut self) {
        self.hash = None;
        if let Some(left) = self.left.as_mut() {
            left.clear_hash();
        }
        if let Some(right) = self.right.as_mut() {
            right.clear_hash();
        }
    }
}
