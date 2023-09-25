use core::fmt;
use std::collections::HashMap;
use std::fmt::Display;

use bitcoin::secp256k1::PublicKey;
use rand_distr::{Distribution, WeightedIndex};

use crate::{NetworkGenerator, SimulationError};

/// The number of times that our network view will try to pick a node that is *not* the source node provided by the
/// caller.
const NETWORK_VIEW_RETRIES: u8 = 5;

/// NetworkGraphView maintains a view of the network graph that can be used to pick nodes by their deployed liquidity
/// and track node capacity within the network. Tracking nodes in the network is memory-expensive, so we use a single
/// tracker for the whole network (in an unbounded environment, we'd make one _per_ node generating random activity,
/// which has a view of the full network except for itself).
pub struct NetworkGraphView {
    node_picker: WeightedIndex<u64>,
    nodes: Vec<(PublicKey, u64)>,
}

impl NetworkGraphView {
    pub fn new(node_capacities: HashMap<PublicKey, u64>) -> Result<Self, SimulationError> {
        // To create a weighted index we're going to need a vector of nodes that we index and weights that are set
        // by their deployed capacity. To efficiently store our view of nodes capacity, we're also going to store
        // capacity along with the node pubkey because we query the two at the same time.
        let nodes = node_capacities.iter().map(|(k, v)| (*k, *v)).collect();

        let node_picker = WeightedIndex::new(node_capacities.into_values().collect::<Vec<u64>>())
            .map_err(|e| SimulationError::RandomActivityError(e.to_string()))?;

        Ok(NetworkGraphView { node_picker, nodes })
    }
}

impl NetworkGenerator for NetworkGraphView {
    /// Randomly samples the network for a node, weighted by capacity.  Using a single graph view means that it's
    /// possible for a source node to select itself. This is masked by allowing muliple retries, though it is possible
    /// that it may still pick the source node in low node-count networks where the source node has proportionally
    /// more capital deployed than other nodes.
    fn sample_node_by_capacity(
        &mut self,
        source: PublicKey,
    ) -> Result<(PublicKey, u64), SimulationError> {
        let mut rng = rand::thread_rng();

        for _ in 0..NETWORK_VIEW_RETRIES {
            let index = self.node_picker.sample(&mut rng);
            let destination = self.nodes[index];

            if destination.0 != source {
                return Ok(destination);
            }
        }

        Err(SimulationError::RandomActivityError(format!(
            "could not pick node that is not source: {source}"
        )))
    }
}

impl Display for NetworkGraphView {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "network graph view with: {} channels", self.nodes.len())
    }
}
