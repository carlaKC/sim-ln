use core::fmt;
use std::collections::HashMap;
use std::fmt::Display;

use bitcoin::secp256k1::PublicKey;
use rand_distr::{Distribution, Exp, LogNormal, WeightedIndex};
use std::time::Duration;

use crate::{NetworkGenerator, PaymentGenerator, SimulationError};

const HOURS_PER_MONTH: u64 = 30 * 24;
const SECONDS_PER_MONTH: u64 = HOURS_PER_MONTH * 60 * 60;

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

/// PaymentActivityGenerator manages generation of random payments for an individual node.
pub struct PaymentActivityGenerator {
    multiplier: f64,
    expected_payment_amt: u64,
    source_capacity: u64,
    event_dist: Exp<f64>,
}

impl PaymentActivityGenerator {
    /// Creates a new activity generator for a node, returning an error if:
    /// - The node has no capacity deployed on the network (we can't send any payments).
    /// - The expected payment amount is more than the source node's capacity (too big to successfully send a payment).
    pub fn new(
        source_capacity_msat: u64,
        expected_payment_amt: u64,
        multiplier: f64,
    ) -> Result<Self, SimulationError> {
        PaymentActivityGenerator::validate_capacity(source_capacity_msat, expected_payment_amt)?;

        // Lamda for the exponential distribution that we'll use to randomly time events is equal to the number of
        // events that we expect to see within our set period.
        let lamda = events_per_month(source_capacity_msat, multiplier, expected_payment_amt)
            / (SECONDS_PER_MONTH as f64);

        let event_dist =
            Exp::new(lamda).map_err(|e| SimulationError::RandomActivityError(e.to_string()))?;

        Ok(PaymentActivityGenerator {
            multiplier,
            expected_payment_amt,
            source_capacity: source_capacity_msat,
            event_dist,
        })
    }

    /// Validates that the generator will be able to generate payment amounts based on the node's capacity and the
    /// simulation's expected payment amount.
    pub fn validate_capacity(
        node_capacity_msat: u64,
        expected_payment_amt: u64,
    ) -> Result<(), SimulationError> {
        // We will not be able to generate payments if the variance of sigma squared for our log normal distribution
        // is > 0 (because we have to take a square root).
        //
        // Sigma squared is calculated as: 2* ln(payment_limit) - ln(expected_payment_amt)
        // Where: payment_limit = node_capacity_msat /2.
        //
        // Therefore we can only process payments if:
        //   2ln(payment_limit) - ln(expected_payment_amt) >= 0
        //   ln(payment_limit)      >= ln(expected_payment_amt)/2
        //   e^ln(payment_limit)    >= e^(ln(expected_payment_amt)/2)
        //   payment_limit          >= sqrt(expected_payment_amt)
        //   node_capacity_msat / 2 >= sqrt(expected_payment_amt)
        //   node_capacity_msat     >= 2 * sqrt(expected_payment_amt)
        let min_required_capacity = 2.0 * f64::sqrt(expected_payment_amt as f64);
        if (node_capacity_msat as f64) < min_required_capacity {
            return Err(SimulationError::RandomActivityError(format!(
                "node needs at least {} capacity (has: {}) to process expected payment amount: {}",
                min_required_capacity, node_capacity_msat, expected_payment_amt
            )));
        }

        Ok(())
    }
}

/// Returns the number of events that the simulation expects the node to process per month based on its capacity, a
/// multiplier which expresses the capital efficiently of the network (how "much" it uses its deployed liquidity) and
/// the expected payment amount for the simulation.
///
/// The total amount that we expect this node to send is capacity * multiplier, because the multiplier is the
/// expression of how many times a node sends its capacity within a month. For example:
/// - A multiplier of 0.5 indicates that the node processes half of its total channel capacity in sends in a month.
/// - A multiplier of 2 indicates that hte node processes twice of its total capacity in sends in a month.
///
/// The number of sends that the simulation will dispatch for this node is simply the total amount that the node is
/// expected to send divided by the expected payment amount (how much we'll send on average) for the simulation.
fn events_per_month(source_capacity_msat: u64, multiplier: f64, expected_payment_amt: u64) -> f64 {
    (source_capacity_msat as f64 * multiplier) / expected_payment_amt as f64
}

impl PaymentGenerator for PaymentActivityGenerator {
    /// Returns the amount of time until the next payment should be scheduled for the node.
    fn next_payment_wait(&mut self) -> Duration {
        let mut rng = rand::thread_rng();
        Duration::from_secs(self.event_dist.sample(&mut rng) as u64)
    }

    /// Returns the payment amount for a payment to a node with the destination capacity provided. The expected value
    /// for the payment is the simulation expected payment amount, and the variance is determined by the channel
    /// capacity of the source and destination node. Variance is calculated such that 95% of payment amounts generated
    /// will fall between the expected payment amount and 50% of the capacity of the node with the least channel
    /// capacity. While the expected value of payments remains the same, scaling variance by node capacity means that
    /// nodes with more deployed capital will see a larger range of payment values than those with smaller total
    /// channel capacity.
    ///
    /// This function will return an error if the payment limit based on channel capacity is too small relative to the
    /// expected payment amount of the simulation. In this case, we won't be able to create a log normal distribution
    /// for this pair, and the payment should be skipped. This is not a critical error, because payments can still
    /// succeed to different destinations (validation ensured that the source capacity was sufficient on creation of
    /// the generator).
    fn payment_amount(&mut self, destination_capacity: u64) -> Result<u64, SimulationError> {
        let payment_limit = std::cmp::min(self.source_capacity, destination_capacity) / 2;

        let ln_pmt_amt = (self.expected_payment_amt as f64).ln();
        let ln_limit = (payment_limit as f64).ln();

        let mu = 2.0 * ln_pmt_amt - ln_limit;
        let sigma_square = 2.0 * ln_limit - ln_pmt_amt;

        if sigma_square < 0.0 {
            return Err(SimulationError::RandomActivityError(format!(
                "payment amount not possible for limit: {payment_limit}, sigma squared: {sigma_square}"
            )));
        }

        let log_normal = LogNormal::new(mu, sigma_square.sqrt())
            .map_err(|e| SimulationError::RandomActivityError(e.to_string()))?;

        let mut rng = rand::thread_rng();
        Ok(log_normal.sample(&mut rng) as u64)
    }
}

impl Display for PaymentActivityGenerator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let monthly_events = events_per_month(
            self.source_capacity,
            self.multiplier,
            self.expected_payment_amt,
        );

        write!(
            f,
            "activity generator for capacity: {} with multiplier {}: {} payments per month ({} per hour)",
            self.source_capacity,
            self.multiplier,
            monthly_events,
            monthly_events / HOURS_PER_MONTH as f64
        )
    }
}
