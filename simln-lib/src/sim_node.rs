use crate::{
    batched_writer::BatchedWriter, clock::Clock, serializers, LightningError, LightningNode,
    NetworkParser, NodeInfo, PaymentOutcome, PaymentResult, SimulationError,
};
use crate::{ShortChannelID, WriteResults};
use async_trait::async_trait;
use bitcoin::constants::ChainHash;
use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Network, ScriptBuf, TxOut};
use lightning::ln::chan_utils::make_funding_redeemscript;
use lightning::ln::features::{ChannelFeatures, NodeFeatures};
use lightning::ln::msgs::{
    LightningError as LdkError, UnsignedChannelAnnouncement, UnsignedChannelUpdate,
};
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::gossip::{NetworkGraph, NodeId};
use lightning::routing::router::{
    find_route, Path, PaymentParameters, Route, RouteHop, RouteParameters,
};
use lightning::routing::scoring::ProbabilisticScorer;
use lightning::routing::utxo::{UtxoLookup, UtxoResult};
use lightning::util::logger::{Level, Logger, Record};
use rand_distr::{Distribution, Poisson};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap};
use std::error::Error;
use std::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use triggered::{Listener, Trigger};

/// ForwardingError represents the various errors that we can run into when forwarding payments in a simulated network.
/// Since we're not using real lightning nodes, these errors are not obfuscated and can be propagated to the sending
/// node and used for analysis.
#[derive(Debug, Error)]
pub enum ForwardingError {
    /// Zero amount htlcs are invalid in the protocol.
    #[error("ZeroAmountHtlc")]
    ZeroAmountHtlc,
    /// The outgoing channel id was not found in the network graph.
    #[error("ChannelNotFound: {0}")]
    ChannelNotFound(ShortChannelID),
    /// The node pubkey provided was not associated with the channel in the network graph.
    #[error("NodeNotFound: {0:?}")]
    NodeNotFound(PublicKey),
    /// The channel has already forwarded an HTLC with the payment hash provided.
    /// TODO: remove if MPP support is added.
    #[error("PaymentHashExists: {0:?}")]
    PaymentHashExists(PaymentHash),
    /// An htlc with the payment hash provided could not be found to resolve.
    #[error("PaymentHashNotFound: {0:?}")]
    PaymentHashNotFound(PaymentHash),
    /// The forwarding node did not have sufficient outgoing balance to forward the htlc (htlc amount / balance).
    #[error("InsufficientBalance: amount: {0} > balance: {1}")]
    InsufficientBalance(u64, u64),
    /// The htlc forwarded is less than the channel's advertised minimum htlc amount (htlc amount / minimum).
    #[error("LessThanMinimum: amount: {0} < minimum: {1}")]
    LessThanMinimum(u64, u64),
    /// The htlc forwarded is more than the channel's advertised maximum htlc amount (htlc amount / maximum).
    #[error("MoreThanMaximum: amount: {0} > maximum: {1}")]
    MoreThanMaximum(u64, u64),
    /// The channel has reached its maximum allowable number of htlcs in flight (total in flight / maximim).
    #[error("ExceedsInFlightCount: total in flight: {0} > maximum count: {1}")]
    ExceedsInFlightCount(u64, u64),
    /// The forwarded htlc's amount would push the channel over its maximum allowable in flight total
    /// (total in flight / maximum).
    #[error("ExceedsInFlightTotal: total in flight amount: {0} > maximum amount: {0}")]
    ExceedsInFlightTotal(u64, u64),
    /// The forwarded htlc's cltv expiry exceeds the maximum value used to express block heights in Bitcoin.
    #[error("ExpiryInSeconds: cltv expressed in seconds: {0}")]
    ExpiryInSeconds(u32, u32),
    /// The forwarded htlc has insufficient cltv delta for the channel's minimum delta (cltv delta / minimum).
    #[error("InsufficientCltvDelta: cltv delta: {0} < required: {1}")]
    InsufficientCltvDelta(u32, u32),
    /// The forwarded htlc has insufficient fee for the channel's policy (fee / expected fee / base fee / prop fee).
    #[error("InsufficientFee: offered fee: {0} (base: {1}, prop: {2}) < expected: {3}")]
    InsufficientFee(u64, u64, u64, u64),
    /// The fee policy for a htlc amount would overflow with the given fee policy (htlc amount / base fee / prop fee).
    #[error("FeeOverflow: htlc amount: {0} (base: {1}, prop: {2})")]
    FeeOverflow(u64, u64, u64),
    /// Sanity check on channel balances failed (node balances / channel capacity).
    #[error("SanityCheckFailed: node balance: {0} != capacity: {1}")]
    SanityCheckFailed(u64, u64),
    #[error("InterceptorError: {0}")]
    InterceptorError(Box<dyn Error + Send + Sync + 'static>),
    #[error("DuplicateCustomRecord: key {0}")]
    DuplicateCustomRecord(u64),
}

impl ForwardingError {
    /// Returns a boolean indicating whether failure to forward a htlc is a critical error that warrants shutdown.
    fn is_critical(&self) -> bool {
        matches!(
            self,
            ForwardingError::ZeroAmountHtlc
                | ForwardingError::ChannelNotFound(_)
                | ForwardingError::NodeNotFound(_)
                | ForwardingError::PaymentHashExists(_)
                | ForwardingError::PaymentHashNotFound(_)
                | ForwardingError::SanityCheckFailed(_, _)
                | ForwardingError::FeeOverflow(_, _, _)
                | ForwardingError::DuplicateCustomRecord(_)
                | ForwardingError::InterceptorError(_)
        )
    }
}

/// Represents an in-flight htlc that has been forwarded over a channel that is awaiting resolution.
#[derive(Copy, Clone)]
struct Htlc {
    amount_msat: u64,
    cltv_expiry: u32,
    add_ts: SystemTime,
    remove_ts: Option<SystemTime>,
}

/// Represents one node in the channel's forwarding policy and restrictions. Note that this doesn't directly map to
/// a single concept in the protocol, a few things have been combined for the sake of simplicity. Used to manage the
/// lightning "state machine" and check that HTLCs are added in accordance of the advertised policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPolicy {
    pub pubkey: PublicKey,
    pub alias: String,
    pub max_htlc_count: u64,
    pub max_in_flight_msat: u64,
    pub min_htlc_size_msat: u64,
    pub max_htlc_size_msat: u64,
    pub cltv_expiry_delta: u32,
    pub base_fee: u64,
    pub fee_rate_prop: u64,
}

impl ChannelPolicy {
    /// Validates that the channel policy is acceptable for the size of the channel.
    fn validate(&self, capacity_msat: u64) -> Result<(), SimulationError> {
        if self.max_in_flight_msat > capacity_msat {
            return Err(SimulationError::SimulatedNetworkError(format!(
                "max_in_flight_msat {} > capacity {}",
                self.max_in_flight_msat, capacity_msat
            )));
        }
        if self.max_htlc_size_msat > capacity_msat {
            return Err(SimulationError::SimulatedNetworkError(format!(
                "max_htlc_size_msat {} > capacity {}",
                self.max_htlc_size_msat, capacity_msat
            )));
        }
        Ok(())
    }
}

/// Fails with the forwarding error provided if the value provided fails its inequality check.
macro_rules! fail_forwarding_inequality {
    ($value_1:expr, $op:tt, $value_2:expr, $error_variant:ident $(, $opt:expr)*) => {
        if $value_1 $op $value_2 {
            return Err(ForwardingError::$error_variant(
                    $value_1,
                    $value_2
                    $(
                        , $opt
                    )*
             ));
        }
    };
}

/// The internal state of one side of a simulated channel, including its forwarding parameters. This struct is
/// primarily responsible for handling our view of what's currently in-flight on the channel, and how much
/// liquidity we have.
#[derive(Clone)]
struct ChannelState {
    local_balance_msat: u64,
    /// Maps payment hash to htlc and index that it was added at.
    in_flight: HashMap<PaymentHash, (Htlc, u64)>,
    policy: ChannelPolicy,
    /// Tracks unique identifier for htlcs proposed by this node (sent in the outgoing direction).
    index: u64,
}

impl ChannelState {
    /// Creates a new channel with local liquidity as allocated by the caller. The responsibility of ensuring that the
    /// local balance of each side of the channel equals its total capacity is on the caller, as we are only dealing
    /// with a one-sided view of the channel's state.
    fn new(policy: ChannelPolicy, local_balance_msat: u64) -> Self {
        ChannelState {
            local_balance_msat,
            in_flight: HashMap::new(),
            policy,
            index: 0,
        }
    }

    /// Returns the sum of all the *in flight outgoing* HTLCs on the channel.
    fn in_flight_total(&self) -> u64 {
        self.in_flight.values().map(|h| h.0.amount_msat).sum()
    }

    /// Checks whether the proposed HTLC abides by the channel policy advertised for using this channel as the
    /// *outgoing* link in a forward.
    fn check_htlc_forward(
        &self,
        cltv_delta: u32,
        amt: u64,
        fee: u64,
    ) -> Result<(), ForwardingError> {
        fail_forwarding_inequality!(cltv_delta, <, self.policy.cltv_expiry_delta, InsufficientCltvDelta);

        let expected_fee = amt
            .checked_mul(self.policy.fee_rate_prop)
            .and_then(|prop_fee| (prop_fee / 1000000).checked_add(self.policy.base_fee))
            .ok_or(ForwardingError::FeeOverflow(
                amt,
                self.policy.base_fee,
                self.policy.fee_rate_prop,
            ))?;

        fail_forwarding_inequality!(
            fee, <, expected_fee, InsufficientFee, self.policy.base_fee, self.policy.fee_rate_prop
        );

        Ok(())
    }

    /// Checks whether the proposed HTLC can be added to the channel as an outgoing HTLC. This requires that we have
    /// sufficient liquidity, and that the restrictions on our in flight htlc balance and count are not violated by
    /// the addition of the HTLC. Specification sanity checks (such as reasonable CLTV) are also included, as this
    /// is where we'd check it in real life.
    fn check_outgoing_addition(&self, htlc: &Htlc) -> Result<(), ForwardingError> {
        fail_forwarding_inequality!(htlc.amount_msat, >, self.policy.max_htlc_size_msat, MoreThanMaximum);
        fail_forwarding_inequality!(htlc.amount_msat, <, self.policy.min_htlc_size_msat, LessThanMinimum);
        fail_forwarding_inequality!(
            self.in_flight.len() as u64 + 1, >, self.policy.max_htlc_count, ExceedsInFlightCount
        );
        fail_forwarding_inequality!(
            self.in_flight_total() + htlc.amount_msat, >, self.policy.max_in_flight_msat, ExceedsInFlightTotal
        );
        fail_forwarding_inequality!(htlc.amount_msat, >, self.local_balance_msat, InsufficientBalance);
        fail_forwarding_inequality!(htlc.cltv_expiry, >, 500000000, ExpiryInSeconds);

        Ok(())
    }

    /// Adds the HTLC to our set of outgoing in-flight HTLCs. [`check_outgoing_addition`] must be called before
    /// this to ensure that the restrictions on outgoing HTLCs are not violated. Local balance is decreased by the
    /// HTLC amount, as this liquidity is no longer available.
    ///
    /// Note: MPP payments are not currently supported, so this function will fail if a duplicate payment hash is
    /// reported.
    fn add_outgoing_htlc(&mut self, hash: PaymentHash, htlc: Htlc) -> Result<u64, ForwardingError> {
        self.check_outgoing_addition(&htlc)?;
        if self.in_flight.get(&hash).is_some() {
            return Err(ForwardingError::PaymentHashExists(hash));
        }
        let index = self.index;
        self.index += 1;

        self.local_balance_msat -= htlc.amount_msat;
        self.in_flight.insert(hash, (htlc, index));

        Ok(index)
    }

    /// Removes the HTLC from our set of outgoing in-flight HTLCs, failing if the payment hash is not found.
    fn remove_outgoing_htlc(&mut self, hash: &PaymentHash) -> Result<(Htlc, u64), ForwardingError> {
        self.in_flight
            .remove(hash)
            .ok_or(ForwardingError::PaymentHashNotFound(*hash))
    }

    // Updates channel state to account for the resolution of an outgoing in-flight HTLC. If the HTLC failed, the
    // balance is failed back to the channel's local balance. If not, the in-flight balance is settled to the other
    // node, so there is no operation.
    fn settle_outgoing_htlc(&mut self, amt: u64, success: bool) {
        if !success {
            self.local_balance_msat += amt
        }
    }

    // Updates channel state to account for the resolution of an incoming in-flight HTLC. If the HTLC succeeded,
    // the balance is settled to the channel's local balance. If not, the in-flight balance is failed back to the
    // other node, so there is no operation.
    fn settle_incoming_htlc(&mut self, amt: u64, success: bool) {
        if success {
            self.local_balance_msat += amt
        }
    }
}

/// Represents a simulated channel, and is responsible for managing addition and removal of HTLCs from the channel and
/// sanity checks. Channel state is tracked *unidirectionally* for each participant in the channel.
///
/// Each node represented in the channel tracks only its outgoing HTLCs, and balance is transferred between the two
/// nodes as they settle or fail. Given some channel: node_1 <----> node_2:
/// * HTLC sent node_1 -> node_2: added to in-flight outgoing htlcs on node_1.
/// * HTLC sent node_2 -> node_1: added to in-flight outgoing htlcs on node_2.
///
/// Rules for managing balance are as follows:
/// * When an HTLC is in flight, the channel's local outgoing liquidity decreases (as it's locked up).
/// * When an HTLC fails, the balance is returned to the local node (the one that it was in-flight / outgoing on).
/// * When an HTLC succeeds, the balance is sent to the remote node (the one that did not track it as in-flight).
///
/// With each state transition, the simulated channel checks that the sum of its local balances and in-flight equal the
/// total channel capacity. Failure of this sanity check represents a critical failure in the state machine.
#[derive(Clone)]
pub struct SimulatedChannel {
    capacity_msat: u64,
    short_channel_id: ShortChannelID,
    node_1: ChannelState,
    node_2: ChannelState,
    forward_only: bool,
}

impl SimulatedChannel {
    /// Creates a new channel with the capacity and policies provided. The total capacity of the channel is evenly split
    /// between the channel participants (this is an arbitrary decision).
    pub fn new(
        capacity_msat: u64,
        short_channel_id: ShortChannelID,
        node_1: ChannelPolicy,
        node_2: ChannelPolicy,
        forward_only: bool,
    ) -> Self {
        SimulatedChannel {
            capacity_msat,
            short_channel_id,
            node_1: ChannelState::new(node_1, capacity_msat / 2),
            node_2: ChannelState::new(node_2, capacity_msat / 2),
            forward_only,
        }
    }

    /// Validates that a simulated channel has distinct node pairs and valid routing policies.
    fn validate(&self) -> Result<(), SimulationError> {
        if self.node_1.policy.pubkey == self.node_2.policy.pubkey {
            return Err(SimulationError::SimulatedNetworkError(format!(
                "Channel should have distinct node pubkeys, got: {} for both nodes.",
                self.node_1.policy.pubkey
            )));
        }

        self.node_1.policy.validate(self.capacity_msat)?;
        self.node_2.policy.validate(self.capacity_msat)?;

        Ok(())
    }

    fn get_node_mut(&mut self, pubkey: &PublicKey) -> Result<&mut ChannelState, ForwardingError> {
        if pubkey == &self.node_1.policy.pubkey {
            Ok(&mut self.node_1)
        } else if pubkey == &self.node_2.policy.pubkey {
            Ok(&mut self.node_2)
        } else {
            Err(ForwardingError::NodeNotFound(*pubkey))
        }
    }

    fn get_node(&self, pubkey: &PublicKey) -> Result<&ChannelState, ForwardingError> {
        if pubkey == &self.node_1.policy.pubkey {
            Ok(&self.node_1)
        } else if pubkey == &self.node_2.policy.pubkey {
            Ok(&self.node_2)
        } else {
            Err(ForwardingError::NodeNotFound(*pubkey))
        }
    }

    /// Adds an htlc to the appropriate side of the simulated channel, checking its policy and balance are okay. The
    /// public key of the node sending the HTLC (ie, the party that would send update_add_htlc in the protocol)
    /// must be provided to add the outgoing htlc to its side of the channel.
    fn add_htlc(
        &mut self,
        sending_node: &PublicKey,
        hash: PaymentHash,
        htlc: Htlc,
    ) -> Result<u64, ForwardingError> {
        if htlc.amount_msat == 0 {
            return Err(ForwardingError::ZeroAmountHtlc);
        }

        let index = self
            .get_node_mut(sending_node)?
            .add_outgoing_htlc(hash, htlc)?;
        self.sanity_check()?;

        Ok(index)
    }

    /// Performs a sanity check on the total balances in a channel. Note that we do not currently include on-chain
    /// fees or reserve so these values should exactly match.
    fn sanity_check(&self) -> Result<(), ForwardingError> {
        let node_1_total = self.node_1.local_balance_msat + self.node_1.in_flight_total();
        let node_2_total = self.node_2.local_balance_msat + self.node_2.in_flight_total();

        fail_forwarding_inequality!(node_1_total + node_2_total, !=, self.capacity_msat, SanityCheckFailed);

        Ok(())
    }

    /// Removes an htlc from the appropriate side of the simulated channel, settling balances across channel sides
    /// based on the success of the htlc. The public key of the node that originally sent the HTLC (ie, the party
    /// that would send update_add_htlc in the protocol) must be provided to remove the htlc from its side of the
    /// channel.
    fn remove_htlc(
        &mut self,
        sending_node: &PublicKey,
        hash: &PaymentHash,
        success: bool,
        remove_time: SystemTime,
    ) -> Result<(Htlc, u64), ForwardingError> {
        let mut htlc = self
            .get_node_mut(sending_node)?
            .remove_outgoing_htlc(hash)?;
        htlc.0.remove_ts = Some(remove_time);

        self.settle_htlc(sending_node, htlc.0.amount_msat, success)?;
        self.sanity_check()?;

        Ok(htlc)
    }

    /// Updates the local balance of each node in the channel once a htlc has been resolved, pushing funds to the
    /// receiving nodes in the case of a successful payment and returning balance to the sender in the case of a
    /// failure.
    fn settle_htlc(
        &mut self,
        sending_node: &PublicKey,
        amount_msat: u64,
        success: bool,
    ) -> Result<(), ForwardingError> {
        if sending_node == &self.node_1.policy.pubkey {
            self.node_1.settle_outgoing_htlc(amount_msat, success);
            self.node_2.settle_incoming_htlc(amount_msat, success);
            Ok(())
        } else if sending_node == &self.node_2.policy.pubkey {
            self.node_2.settle_outgoing_htlc(amount_msat, success);
            self.node_1.settle_incoming_htlc(amount_msat, success);
            Ok(())
        } else {
            Err(ForwardingError::NodeNotFound(*sending_node))
        }
    }

    /// Checks an htlc forward against the outgoing policy of the node provided.
    fn check_htlc_forward(
        &self,
        forwarding_node: &PublicKey,
        cltv_delta: u32,
        amount_msat: u64,
        fee_msat: u64,
    ) -> Result<(), ForwardingError> {
        self.get_node(forwarding_node)?
            .check_htlc_forward(cltv_delta, amount_msat, fee_msat)
    }
}

impl From<NetworkParser> for SimulatedChannel {
    fn from(network_parser: NetworkParser) -> Self {
        SimulatedChannel::new(
            network_parser.capacity_msat,
            network_parser.scid,
            network_parser.node_1,
            network_parser.node_2,
            network_parser.forward_only,
        )
    }
}

/// SimNetwork represents a high level network coordinator that is responsible for the task of actually propagating
/// payments through the simulated network.
#[async_trait]
trait SimNetwork: Send + Sync {
    /// Sends payments over the route provided through the network, reporting the final payment outcome to the sender
    /// channel provided.
    fn dispatch_payment(
        &mut self,
        source: PublicKey,
        route: Route,
        payment_hash: PaymentHash,
        sender: Sender<Result<PaymentResult, LightningError>>,
    );

    /// Looks up a node in the simulated network and a list of its channel capacities.
    async fn lookup_node(&self, node: &PublicKey) -> Result<(NodeInfo, Vec<u64>), LightningError>;
}

/// A wrapper struct used to implement the LightningNode trait (can be thought of as "the" lightning node). Passes
/// all functionality through to a coordinating simulation network. This implementation contains both the [`SimNetwork`]
/// implementation that will allow us to dispatch payments and a read-only NetworkGraph that is used for pathfinding.
/// While these two could be combined, we re-use the LDK-native struct to allow re-use of their pathfinding logic.
struct SimNode<'a, T: SimNetwork> {
    info: NodeInfo,
    /// The underlying execution network that will be responsible for dispatching payments.
    network: Arc<Mutex<T>>,
    /// Tracks the channel that will provide updates for payments by hash.
    in_flight: HashMap<PaymentHash, Receiver<Result<PaymentResult, LightningError>>>,
    /// A read-only graph used for pathfinding.
    pathfinding_graph: Arc<NetworkGraph<&'a WrappedLog>>,
}

impl<'a, T: SimNetwork> SimNode<'a, T> {
    /// Creates a new simulation node that refers to the high level network coordinator provided to process payments
    /// on its behalf. The pathfinding graph is provided separately so that each node can handle its own pathfinding.
    pub fn new(
        info: NodeInfo,
        payment_network: Arc<Mutex<T>>,
        pathfinding_graph: Arc<NetworkGraph<&'a WrappedLog>>,
    ) -> Self {
        SimNode {
            info,
            network: payment_network,
            in_flight: HashMap::new(),
            pathfinding_graph,
        }
    }
}

/// Produces the node info for a mocked node, filling in the features that the simulator requires.
pub fn node_info(pubkey: PublicKey, alias: String) -> NodeInfo {
    // Set any features that the simulator requires here.
    let mut features = NodeFeatures::empty();
    features.set_keysend_optional();

    NodeInfo {
        pubkey,
        alias,
        features,
    }
}

/// Uses LDK's pathfinding algorithm with default parameters to find a path from source to destination, with no
/// restrictions on fee budget.
fn find_payment_route(
    source: &PublicKey,
    dest: PublicKey,
    amount_msat: u64,
    pathfinding_graph: &NetworkGraph<&WrappedLog>,
) -> Result<Route, SimulationError> {
    let scorer = ProbabilisticScorer::new(Default::default(), pathfinding_graph, &WrappedLog {});

    find_route(
        source,
        &RouteParameters {
            payment_params: PaymentParameters::from_node_id(dest, 0)
                .with_max_total_cltv_expiry_delta(u32::MAX)
                // TODO: set non-zero value to support MPP.
                .with_max_path_count(1)
                // Allow sending htlcs up to 50% of the channel's capacity.
                .with_max_channel_saturation_power_of_half(1),
            final_value_msat: amount_msat,
            max_total_routing_fee_msat: None,
        },
        pathfinding_graph,
        None,
        &WrappedLog {},
        &scorer,
        &Default::default(),
        &[0; 32],
    )
    .map_err(|e| SimulationError::SimulatedNetworkError(e.err))
}

#[async_trait]
impl<T: SimNetwork> LightningNode for SimNode<'_, T> {
    fn get_info(&self) -> &NodeInfo {
        &self.info
    }

    async fn get_network(&mut self) -> Result<Network, LightningError> {
        Ok(Network::Regtest)
    }

    /// send_payment picks a random preimage for a payment, dispatches it in the network and adds a tracking channel
    /// to our node state to be used for subsequent track_payment calls.
    async fn send_payment(
        &mut self,
        dest: PublicKey,
        amount_msat: u64,
    ) -> Result<PaymentHash, LightningError> {
        // Create a sender and receiver pair that will be used to report the results of the payment and add them to
        // our internal tracking state along with the chosen payment hash.
        let (sender, receiver) = channel();
        let preimage = PaymentPreimage(rand::random());
        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

        // Check for payment hash collision, failing the payment if we happen to repeat one.
        match self.in_flight.entry(payment_hash) {
            Entry::Occupied(_) => {
                return Err(LightningError::SendPaymentError(
                    "payment hash exists".to_string(),
                ));
            },
            Entry::Vacant(vacant) => {
                vacant.insert(receiver);
            },
        }

        let route = match find_payment_route(
            &self.info.pubkey,
            dest,
            amount_msat,
            &self.pathfinding_graph,
        ) {
            Ok(path) => path,
            // In the case that we can't find a route for the payment, we still report a successful payment *api call*
            // and report RouteNotFound to the tracking channel. This mimics the behavior of real nodes.
            Err(e) => {
                log::trace!("Could not find path for payment: {:?}.", e);

                if let Err(e) = sender.send(Ok(PaymentResult {
                    htlc_count: 0,
                    payment_outcome: PaymentOutcome::RouteNotFound,
                })) {
                    log::error!("Could not send payment result: {:?}.", e);
                }

                return Ok(payment_hash);
            },
        };

        // If we did successfully obtain a route, dispatch the payment through the network and then report success.
        self.network
            .lock()
            .await
            .dispatch_payment(self.info.pubkey, route, payment_hash, sender);

        Ok(payment_hash)
    }

    /// track_payment blocks until a payment outcome is returned for the payment hash provided, or the shutdown listener
    /// provided is triggered. This call will fail if the hash provided was not obtained by calling send_payment first.
    async fn track_payment(
        &mut self,
        hash: &PaymentHash,
        listener: Listener,
    ) -> Result<PaymentResult, LightningError> {
        match self.in_flight.remove(hash) {
            Some(receiver) => {
                select! {
                    biased;
                    _ = listener => Err(
                        LightningError::TrackPaymentError("shutdown during payment tracking".to_string()),
                    ),

                    // If we get a payment result back, remove from our in flight set of payments and return the result.
                    res = receiver => {
                        res.map_err(|e| LightningError::TrackPaymentError(format!("channel receive err: {}", e)))?
                    },
                }
            },
            None => Err(LightningError::TrackPaymentError(format!(
                "payment hash {} not found",
                hex::encode(hash.0),
            ))),
        }
    }

    async fn get_node_info(&mut self, node_id: &PublicKey) -> Result<NodeInfo, LightningError> {
        Ok(self.network.lock().await.lookup_node(node_id).await?.0)
    }

    async fn list_channels(&mut self) -> Result<Vec<u64>, LightningError> {
        Ok(self
            .network
            .lock()
            .await
            .lookup_node(&self.info.pubkey)
            .await?
            .1)
    }
}

/// Stores information about simulated nodes for quick lookup.
struct GraphNodeInfo {
    channel_capacities: Vec<(u64, bool)>,
    alias: String,
}

impl GraphNodeInfo {
    fn new(channel_capacities: Vec<(u64, bool)>, alias: String) -> Self {
        GraphNodeInfo {
            channel_capacities,
            alias,
        }
    }
}

#[async_trait]
pub trait Interceptor: Send + Sync {
    /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
    async fn intercept_htlc(&self, req: InterceptRequest);

    /// Notifies the interceptor that a previously intercepted htlc has been resolved. Default implementation is a no-op
    /// for cases where the interceptor only cares about interception, not resolution of htlcs.
    async fn notify_resolution(
        &self,
        _res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        Ok(())
    }

    /// Returns an identifying name for the interceptor for logging, does not need to be unique.
    fn name(&self) -> String;
}

/// Notification sent to an external interceptor notifying that a htlc that was previously intercepted has been
/// resolved.
pub struct InterceptResolution {
    /// The node that is forwarding this HTLC.
    pub forwarding_node: PublicKey,

    /// Unique identifier for the incoming htlc.
    pub incoming_htlc: HtlcRef,

    /// The short channel id for the outgoing channel that this htlc should be forwarded over, None if notifying the
    /// receiving node.
    pub outgoing_channel_id: Option<ShortChannelID>,

    /// True if the htlc was settled successfully.
    pub success: bool,
}

/// Request sent to an external interceptor to provide feedback on the resolution of the HTLC.
#[derive(Debug)]
#[allow(dead_code)]
pub struct InterceptRequest {
    /// The node that is forwarding this HTLC.
    pub forwarding_node: PublicKey,

    /// The short channel id for the incoming channel that this htlc was delivered on.
    pub incoming_htlc: HtlcRef,

    /// Custom records provided by the incoming htlc.
    pub incoming_custom_records: CustomRecords,

    /// The short channel id for the outgoing channel that this htlc should be forwarded over.
    pub outgoing_channel_id: Option<ShortChannelID>,

    /// The amount that was forwarded to over the incoming_channel_id.
    pub incoming_amount_msat: u64,

    /// The amount that will be forwarded over outgoing_channel_id.
    pub outgoing_amount_msat: u64,

    /// The expiry height on the incoming htlc.
    pub incoming_expiry_height: u32,

    /// The expiry height on the outgoing htlc.
    pub outgoing_expiry_height: u32,

    /// Channel to send a single interception response on. This channel will be closed if the caller no longer requires
    /// input from the interceptor. This will happen if another interceptor has returned with a HTLC fail/error, or the
    /// simulator is shutting down.
    ///
    /// Callers that wish to exit early *may* listen on [`Sender::closed`]. Handlers that do not watch for closed
    /// channels *must* expect [`tokio::sync::mpsc::error::SendError`] when they call [`Sender::send()`] and the
    /// interceptor is no longer required.
    ///
    /// The top level of the nested result is used to indicate that the interceptor call succeeded, and the inner
    /// result represents an instruction to forward or fail the payment itself. In the case of successful forward,
    /// an optional set of custom records may be provided which will be forwarded to the next hop in the route. Records
    /// from different interceptors are merged, and may not provide conflicting values for the same key.
    pub response: tokio::sync::mpsc::Sender<
        Result<Result<CustomRecords, ForwardingError>, Box<dyn Error + Send + Sync + 'static>>,
    >,
}

impl InterceptRequest {
    fn new(
        hop: RouteHop,
        incoming_amount_msat: u64,
        incoming_htlc: HtlcRef,
        incoming_custom_records: CustomRecords,
        outgoing_channel_id: Option<ShortChannelID>,
        incoming_expiry_height: u32,
        response: tokio::sync::mpsc::Sender<
            Result<Result<CustomRecords, ForwardingError>, Box<dyn Error + Send + Sync + 'static>>,
        >,
    ) -> Self {
        Self {
            forwarding_node: hop.pubkey,
            outgoing_channel_id,
            incoming_amount_msat,
            incoming_htlc,
            incoming_custom_records,
            outgoing_amount_msat: incoming_amount_msat - hop.fee_msat,
            incoming_expiry_height,
            outgoing_expiry_height: incoming_expiry_height - hop.cltv_expiry_delta,
            response,
        }
    }
}

impl Display for InterceptRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "htlc forwarded by {} over {}:{} -> {} forward amounts {} {}",
            self.forwarding_node,
            self.incoming_htlc.channel_id,
            self.incoming_htlc.index,
            {
                if let Some(c) = self.outgoing_channel_id {
                    format!("-> {c}")
                } else {
                    "receive".to_string()
                }
            },
            self.incoming_amount_msat,
            self.outgoing_amount_msat
        )
    }
}

pub type CustomRecords = HashMap<u64, Vec<u8>>;

#[derive(Clone, Debug)]
pub struct HtlcRef {
    pub channel_id: ShortChannelID,
    pub index: u64,
}

/// Graph is the top level struct that is used to coordinate simulation of lightning nodes.
pub struct SimGraph {
    /// nodes caches the list of nodes in the network with a vector of their channel capacities, only used for quick
    /// lookup.
    nodes: HashMap<PublicKey, GraphNodeInfo>,

    /// channels maps the scid of a channel to its current simulation state.
    channels: Arc<Mutex<HashMap<ShortChannelID, SimulatedChannel>>>,

    /// track all tasks spawned to process payments in the graph.
    tasks: JoinSet<()>,

    clock: Arc<dyn Clock>,

    /// Optional writer to flush htlc forwards to disk.
    writer: Option<Arc<Mutex<BatchedWriter>>>,

    /// Optional set of interceptors that will be called every time a HTLC is added to a simulated channel. Given
    /// a route A -- B -- C, events will happen in the following order:
    ///
    interceptors: Vec<Arc<dyn Interceptor>>,

    /// listen for the instruction to shut down.
    shutdown_listener: Listener,

    /// trigger shutdown if a critical error occurs.
    shutdown_trigger: Trigger,
}

impl SimGraph {
    /// Creates a graph on which to simulate payments.
    pub fn new(
        graph_channels: Vec<SimulatedChannel>,
        clock: Arc<dyn Clock>,
        write_results: Option<WriteResults>,
        interceptors: Vec<Arc<dyn Interceptor>>,
        shutdown_listener: Listener,
        shutdown_trigger: Trigger,
    ) -> Result<Self, SimulationError> {
        let mut nodes: HashMap<PublicKey, GraphNodeInfo> = HashMap::new();
        let mut channels = HashMap::new();

        for channel in graph_channels.iter() {
            // Assert that the channel is valid and that its short channel ID is unique within the simulation, required
            // because we use scid to identify the channel.
            channel.validate()?;
            match channels.entry(channel.short_channel_id) {
                Entry::Occupied(_) => {
                    return Err(SimulationError::SimulatedNetworkError(format!(
                        "Simulated short channel ID should be unique: {} duplicated",
                        channel.short_channel_id
                    )))
                },
                Entry::Vacant(v) => v.insert(channel.clone()),
            };

            // It's okay to have duplicate pubkeys because one node can have many channels.
            for node in [&channel.node_1, &channel.node_2] {
                match nodes.entry(node.policy.pubkey) {
                    Entry::Occupied(o) => o
                        .into_mut()
                        .channel_capacities
                        .push((channel.capacity_msat, channel.forward_only)),
                    Entry::Vacant(v) => {
                        v.insert(GraphNodeInfo::new(
                            vec![(channel.capacity_msat, channel.forward_only)],
                            node.policy.alias.clone(),
                        ));
                    },
                }
            }
        }

        // Once off create the file we'll be writing to and add our own headers.
        let writer = if let Some(w) = write_results {
            // TODO: use simulation error not lightning error in this function
            let writer =
                BatchedWriter::new(w.results_dir, "htlc_forwards.csv".to_string(), w.batch_size)?;
            Some(Arc::new(Mutex::new(writer)))
        } else {
            None
        };

        Ok(SimGraph {
            nodes,
            channels: Arc::new(Mutex::new(channels)),
            clock,
            writer,
            tasks: JoinSet::new(),
            interceptors,
            shutdown_listener,
            shutdown_trigger,
        })
    }

    /// Blocks until all tasks created by the simulator have shut down. This function does not trigger shutdown,
    /// because it expects erroring-out tasks to handle their own shutdown triggering.
    pub async fn wait_for_shutdown(&mut self) {
        log::debug!("Waiting for simulated graph to shutdown.");

        while let Some(res) = self.tasks.join_next().await {
            if let Err(e) = res {
                log::error!("Graph task exited with error: {e}");
            }
        }

        // If we're shutting down, force-flush any pending writes to disk.
        if let Some(w) = self.writer.clone() {
            if let Err(e) = w.lock().await.write(true) {
                log::error!("Failed to flush forwards to disk: {e}");
            }
        }

        log::debug!("Simulated graph shutdown.");
    }
}

/// Produces a map of node public key to lightning node implementation to be used for simulations.
pub async fn ln_node_from_graph<'a>(
    graph: Arc<Mutex<SimGraph>>,
    routing_graph: Arc<NetworkGraph<&'a WrappedLog>>,
) -> HashMap<PublicKey, Arc<Mutex<dyn LightningNode + '_>>> {
    let mut nodes: HashMap<PublicKey, Arc<Mutex<dyn LightningNode>>> = HashMap::new();

    for (pk, info) in graph.lock().await.nodes.iter() {
        // Channels that are forward-only should be handled by our simulated graph, but not surfaced for the simulator
        // to generate activity on (they're only there to forward payments). If we have a node which only has such
        // channels, we exclude it completely.
        if info.channel_capacities.iter().all(|c| c.1) {
            log::debug!(
                "Node: {} ({pk}) only has forward-only channels, not including in simulation",
                info.alias
            );

            continue;
        }

        nodes.insert(
            *pk,
            Arc::new(Mutex::new(SimNode::new(
                node_info(*pk, info.alias.clone()),
                graph.clone(),
                routing_graph.clone(),
            ))),
        );
    }

    nodes
}

/// Populates a network graph based on the set of simulated channels provided. This function *only* applies channel
/// announcements, which has the effect of adding the nodes in each channel to the graph, because LDK does not export
/// all of the fields required to apply node announcements. This means that we will not have node-level information
/// (such as features) available in the routing graph.
pub fn populate_network_graph<'a>(
    channels: Vec<SimulatedChannel>,
    clock: Arc<dyn Clock>,
) -> Result<NetworkGraph<&'a WrappedLog>, LdkError> {
    let graph = NetworkGraph::new(Network::Regtest, &WrappedLog {});

    let chain_hash = ChainHash::using_genesis_block(Network::Regtest);

    for channel in channels {
        let announcement = UnsignedChannelAnnouncement {
            // For our purposes we don't currently need any channel level features.
            features: ChannelFeatures::empty(),
            chain_hash,
            short_channel_id: channel.short_channel_id.into(),
            node_id_1: NodeId::from_pubkey(&channel.node_1.policy.pubkey),
            node_id_2: NodeId::from_pubkey(&channel.node_2.policy.pubkey),
            // Note: we don't need bitcoin keys for our purposes, so we just copy them *but* remember that we do use
            // this for our fake utxo validation so they do matter for producing the script that we mock validate.
            bitcoin_key_1: NodeId::from_pubkey(&channel.node_1.policy.pubkey),
            bitcoin_key_2: NodeId::from_pubkey(&channel.node_2.policy.pubkey),
            // Internal field used by LDK, we don't need it.
            excess_data: Vec::new(),
        };

        let utxo_validator = UtxoValidator {
            amount_sat: channel.capacity_msat / 1000,
            script: make_funding_redeemscript(
                &channel.node_1.policy.pubkey,
                &channel.node_2.policy.pubkey,
            )
            .to_v0_p2wsh(),
        };

        graph.update_channel_from_unsigned_announcement(&announcement, &Some(&utxo_validator))?;

        // The least significant bit of the channel flag field represents the direction that the channel update
        // applies to. This value is interpreted as node_1 if it is zero, and node_2 otherwise.
        for (i, node) in [channel.node_1, channel.node_2].iter().enumerate() {
            let update = UnsignedChannelUpdate {
                chain_hash,
                short_channel_id: channel.short_channel_id.into(),
                timestamp: clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
                flags: i as u8,
                cltv_expiry_delta: node.policy.cltv_expiry_delta as u16,
                htlc_minimum_msat: node.policy.min_htlc_size_msat,
                htlc_maximum_msat: node.policy.max_htlc_size_msat,
                fee_base_msat: node.policy.base_fee as u32,
                fee_proportional_millionths: node.policy.fee_rate_prop as u32,
                excess_data: Vec::new(),
            };
            graph.update_channel_unsigned(&update)?;
        }
    }

    Ok(graph)
}

#[async_trait]
impl SimNetwork for SimGraph {
    /// dispatch_payment asynchronously propagates a payment through the simulated network, returning a tracking
    /// channel that can be used to obtain the result of the payment. At present, MPP payments are not supported.
    /// In future, we'll allow multiple paths for a single payment, so we allow the trait to accept a route with
    /// multiple paths to avoid future refactoring.
    fn dispatch_payment(
        &mut self,
        source: PublicKey,
        route: Route,
        payment_hash: PaymentHash,
        sender: Sender<Result<PaymentResult, LightningError>>,
    ) {
        // Expect at least one path (right now), with the intention to support multiple in future.
        let path = match route.paths.first() {
            Some(p) => p,
            None => {
                log::warn!("Find route did not return expected number of paths.");

                if let Err(e) = sender.send(Ok(PaymentResult {
                    htlc_count: 0,
                    payment_outcome: PaymentOutcome::RouteNotFound,
                })) {
                    log::error!("Could not send payment result: {:?}.", e);
                }

                return;
            },
        };

        self.tasks.spawn(propagate_payment(PropagatePaymentRequest {
            nodes: self.channels.clone(),
            source,
            route: path.clone(),
            payment_hash,
            interceptors: self.interceptors.clone(),
            listener: self.shutdown_listener.clone(),
            sender,
            writer: self.writer.clone(),
            clock: self.clock.clone(),
            shutdown: self.shutdown_trigger.clone(),
        }));
    }

    /// lookup_node fetches a node's information and channel capacities.
    async fn lookup_node(
        &self,
        pubkey: &PublicKey,
    ) -> Result<(NodeInfo, Vec<u64>), LightningError> {
        self.nodes
            .get(pubkey)
            .map(|sim_node_info| {
                (
                    node_info(*pubkey, sim_node_info.alias.clone()),
                    sim_node_info
                        .channel_capacities
                        .iter()
						// We only want channels that are *not* forward only.
                        .filter(|c| {
							if c.1{
								log::trace!("Skipping channel for: {} with capacity {} due to forward only.",
									sim_node_info.alias, c.0)
							}
							!c.1
						})
                        .map(|c| c.0)
                        .collect(),
                )
            })
            .ok_or(LightningError::GetNodeInfoError(
                "Node not found".to_string(),
            ))
    }
}

/// Adds htlcs to the simulation state along the path provided. Returning the index in the path from which to fail
/// back htlcs (if any) and a forwarding error if the payment is not successfully added to the entire path.
///
/// For each hop in the route, we check both the addition of the HTLC and whether we can forward it. Take an example
/// route A --> B --> C, we will add this in two hops: A --> B then B -->C. For each hop, using A --> B as an example:
/// * Check whether A can add the outgoing HTLC (checks liquidity and in-flight restrictions).
///   * If no, fail the HTLC.
///   * If yes, add outgoing HTLC to A's channel.
/// * Check whether B will accept the forward.
///   * If no, fail the HTLC.
///   * If yes, continue to the next hop.
///
/// If successfully added to A --> B, this check will be repeated for B --> C.
///
/// Note that we don't have any special handling for the receiving node, once we've successfully added a outgoing HTLC
/// for the outgoing channel that is connected to the receiving node we'll return. To add invoice-related handling,
/// we'd need to include some logic that then decides whether to settle/fail the HTLC at the last hop here.
async fn add_htlcs(
    nodes: Arc<Mutex<HashMap<ShortChannelID, SimulatedChannel>>>,
    source: PublicKey,
    route: Path,
    payment_hash: PaymentHash,
    clock: Arc<dyn Clock>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    listener: Listener,
) -> Result<(), (Option<usize>, ForwardingError)> {
    let mut outgoing_node = source;
    let mut outgoing_amount = route.fee_msat() + route.final_value_msat();
    let mut outgoing_cltv = route.hops.iter().map(|hop| hop.cltv_expiry_delta).sum();

    // Start with no custom records on the htlc (we don't have the ability to set them at the moment
    let mut incoming_custom_records = HashMap::new();

    // Tracks the hop index that we need to remove htlcs from on payment completion (both success and failure).
    // Given a payment from A to C, over the route A -- B -- C, this index has the following meanings:
    // - None: A could not add the outgoing HTLC to B, no action for payment failure.
    // - Some(0): A -- B added the HTLC but B could not forward the HTLC to C, so it only needs removing on A -- B.
    // - Some(1): A -- B and B -- C added the HTLC, so it should be removed from the full route.
    let mut fail_idx = None;
    let last_hop = route.hops.len() - 1;
    for (i, hop) in route.hops.iter().enumerate() {
        // Lock the node that we want to add the HTLC to next. We choose to lock one hop at a time (rather than for
        // the whole route) so that we can mimic the behavior of payments in the real network where the HTLCs in a
        // route don't all get to lock in in a row (they have interactions with other payments).
        let mut node_lock = nodes.lock().await;
        let scid = ShortChannelID::from(hop.short_channel_id);

        let (incoming_htlc, next_scid) = {
            if let Some(channel) = node_lock.get_mut(&scid) {
                let htlc_index = channel
                .add_htlc(
                    &outgoing_node,
                    payment_hash,
                    Htlc {
                        amount_msat: outgoing_amount,
                        cltv_expiry: outgoing_cltv,
                        add_ts: clock.now(),
                        remove_ts: None,
                    },
                )
                // If we couldn't add to this HTLC, we only need to fail back from the preceding hop, so we don't
                // have to progress our fail_idx.
                .map_err(|e| (fail_idx, e))?;

                // If the HTLC was successfully added, then we'll need to remove the HTLC from this channel if we fail,
                // so we progress our failure index to include this node.
                fail_idx = Some(i);

                // Once we've added the HTLC on this hop's channel, we want to check whether it has sufficient fee
                // and CLTV delta per the _next_ channel's policy (because fees and CLTV delta in LN are charged on
                // the outgoing link). We check the policy belonging to the node that we just forwarded to, which
                // represents the fee in that direction.
                //
                // TODO: add invoice-related checks (including final CTLV) if we support non-keysend payments.
                let mut next_scid = None;
                if i != last_hop {
                    next_scid = Some(ShortChannelID::from(route.hops[i + 1].short_channel_id));

                    if let Some(channel) = node_lock.get(&next_scid.unwrap()) {
                        channel
                        .check_htlc_forward(
                            &hop.pubkey,
                            hop.cltv_expiry_delta,
                            outgoing_amount - hop.fee_msat,
                            hop.fee_msat,
                        )
                        // If we haven't met forwarding conditions for the next channel's policy, then we fail at
                        // the current index, because we've already added the HTLC as outgoing.
                        .map_err(|e| (fail_idx, e))?;
                    }
                }

                (
                    HtlcRef {
                        channel_id: scid,
                        index: htlc_index,
                    },
                    next_scid,
                )
            } else {
                return Err((fail_idx, ForwardingError::ChannelNotFound(scid)));
            }
        };

        // Before we continue on to the next hop, we'll call any interceptors registered to get external input on the
        // forwarding decision for this HTLC.
        //
        // We drop our node lock so that we can await our interceptors (which may choose to hold the HTLC for a long
        // time) without holding our entire graph hostage.
        drop(node_lock);

        // Collect any custom records set by the interceptor for the outgoing link. We could overload
        // incoming_custom_records for this purpose, but we keep it simple for now.
        let mut outgoing_custom_records: HashMap<u64, Vec<u8>> = HashMap::new();

        if interceptors.is_empty() {
            let (sender, mut receiver) = tokio::sync::mpsc::channel(interceptors.len());
            for interceptor in interceptors.iter() {
                let request = InterceptRequest::new(
                    hop.clone(),
                    // We've just added the outgoing amount to the sending node, and we're notifying the forward to its
                    // peer that has just received an incoming htlc, so the outgoing amount added to the sending node
                    // is the incoming amount for the forwarding node.
                    outgoing_amount,
                    incoming_htlc.clone(),
                    incoming_custom_records.clone(),
                    next_scid,
                    outgoing_cltv,
                    sender.clone(),
                );

                log::trace!(
                    "Sending HTLC to intercepor: {} {request}",
                    interceptor.name()
                );
                interceptor.intercept_htlc(request).await;
            }

            // Read results from all of our interceptors, tracking whether any of them returned an instruction to fail
            // the HTLC. Once we get a terminal signal (a shutdown or HTLC failure), we'll close the receiving channel
            // and drain any remaining messages to ensure that we do not block any callers.
            let mut interceptor_failure = None;
            'get_resp: for i in 0..interceptors.len() {
                log::trace!("Waiting for interceptor: {i}");

                select! {
                biased;
                _ = listener.clone() => {
                    receiver.close();
                },
                resp = receiver.recv() =>{
                        match resp {
                            // Interceptor call succeeded and indicated that we should proceed with the forward. Merge
                            // any custom records provided, failing if interceptors provide duplicate values for the
                            // same key.
                            Some(Ok(Ok(records))) => {
                                for (k, v) in records{
                                    match outgoing_custom_records.entry(k){
                                        Entry::Occupied(e) => {
                                            let existing_value = e.get();
                                            if *existing_value != v {
                                                return Err((fail_idx, ForwardingError::DuplicateCustomRecord(k)))
                                            }
                                        },
                                        Entry::Vacant(e) => {e.insert(v);},
                                    };
                                }
                            },
                            // Interceptor call succeeded, but it indicated that we should not proceed with the forward.
                            Some(Ok(Err(f))) => {
                                interceptor_failure = Some(f);
                                receiver.close();
                            }
                            // If the interceptor call itself failed, we need to shut down the full simulation because
                            // something has errored out.
                            Some(Err(e)) => {
                                return Err((fail_idx, ForwardingError::InterceptorError(e)))
                            },
                            None => break 'get_resp
                        }
                    },
                }
            }

            if let Some(f) = interceptor_failure {
                return Err((fail_idx, f));
            }
        }

        // Once we've taken the "hop" to the destination pubkey, it becomes the source of the next outgoing htlc and
        // any outgoing custom records set by the interceptor become the incoming custom records for the next hop.
        outgoing_node = hop.pubkey;
        outgoing_amount -= hop.fee_msat;
        outgoing_cltv -= hop.cltv_expiry_delta;
        incoming_custom_records = outgoing_custom_records;
    }

    Ok(())
}

/// Removes htlcs from the simulation state from the index in the path provided (backwards).
///
/// Taking the example of a payment over A --> B --> C --> D where the payment was rejected by C because it did not
/// have enough liquidity to forward it, we will expect a failure index of 1 because the HTLC was successfully added
/// to A and B's outgoing channels, but not C.
///
/// This function will remove the HTLC one hop at a time, working backwards from the failure index, so in this
/// case B --> C and then B --> A. We lookup the HTLC on the incoming node because it will have tracked it in its
/// outgoing in-flight HTLCs.
async fn remove_htlcs(
    nodes: Arc<Mutex<HashMap<ShortChannelID, SimulatedChannel>>>,
    resolution_idx: usize,
    source: PublicKey,
    route: Path,
    payment_hash: PaymentHash,
    success: bool,
    clock: Arc<dyn Clock>,
    interceptors: Vec<Arc<dyn Interceptor>>,
) -> Result<Vec<Htlc>, ForwardingError> {
    let mut route_htlcs: Vec<Htlc> = vec![];

    let mut outgoing_channel_id = None;
    for (i, hop) in route.hops[0..=resolution_idx].iter().enumerate().rev() {
        // When we add HTLCs, we do so on the state of the node that sent the htlc along the channel so we need to
        // look up our incoming node so that we can remove it when we go backwards. For the first htlc, this is just
        // the sending node, otherwise it's the hop before.
        let incoming_node = if i == 0 {
            source
        } else {
            route.hops[i - 1].pubkey
        };

        // As with when we add HTLCs, we remove them one hop at a time (rather than locking for the whole route) to
        // mimic the behavior of payments in a real network.
        let mut node_lock = nodes.lock().await;
        let incoming_scid = ShortChannelID::from(hop.short_channel_id);
        let (removed_htlc, index) = match node_lock.get_mut(&incoming_scid) {
            Some(channel) => {
                channel.remove_htlc(&incoming_node, &payment_hash, success, clock.now())?
            },
            None => {
                return Err(ForwardingError::ChannelNotFound(ShortChannelID::from(
                    hop.short_channel_id,
                )))
            },
        };

        // Add removed htlc to list of htlcs.
        route_htlcs.push(removed_htlc);

        // We drop our node lock so that we can notify interceptors without blocking other payments processing.
        drop(node_lock);

        for interceptor in interceptors.iter() {
            log::trace!("Sending resolution to interceptor: {}", interceptor.name());

            interceptor
                .notify_resolution(InterceptResolution {
                    forwarding_node: hop.pubkey,
                    incoming_htlc: HtlcRef {
                        channel_id: incoming_scid,
                        index,
                    },
                    outgoing_channel_id,
                    success,
                })
                .await
                .map_err(ForwardingError::InterceptorError)?;
        }

        outgoing_channel_id = Some(incoming_scid);
    }

    Ok(route_htlcs.into_iter().rev().collect())
}

struct PropagatePaymentRequest {
    nodes: Arc<Mutex<HashMap<ShortChannelID, SimulatedChannel>>>,
    source: PublicKey,
    route: Path,
    payment_hash: PaymentHash,
    sender: Sender<Result<PaymentResult, LightningError>>,
    writer: Option<Arc<Mutex<BatchedWriter>>>,
    clock: Arc<dyn Clock>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    listener: Listener,
    shutdown: Trigger,
}

/// Finds a payment path from the source to destination nodes provided, and propagates the appropriate htlcs through
/// the simulated network, notifying the sender channel provided of the payment outcome. If a critical error occurs,
/// ie a breakdown of our state machine, it will still notify the payment outcome and will use the shutdown trigger
/// to signal that we should exit.
async fn propagate_payment(request: PropagatePaymentRequest) {
    // If we partially added HTLCs along the route, we need to fail them back to the source to clean up our partial
    // state. It's possible that we failed with the very first add, and then we don't need to clean anything up.
    let notify_result = if let Err((fail_idx, err)) = add_htlcs(
        request.nodes.clone(),
        request.source,
        request.route.clone(),
        request.payment_hash,
        request.clock.clone(),
        request.interceptors.clone(),
        request.listener,
    )
    .await
    {
        if err.is_critical() {
            request.shutdown.trigger();
        }

        if let Some(resolution_idx) = fail_idx {
            if let Err(e) = remove_htlcs(
                request.nodes,
                resolution_idx,
                request.source,
                request.route,
                request.payment_hash,
                false,
                request.clock.clone(),
                request.interceptors.clone(),
            )
            .await
            {
                if e.is_critical() {
                    request.shutdown.trigger();
                }
            }
        }

        // We have more information about failures because we're in control of the whole route, so we log the
        // actual failure reason and then fail back with unknown failure type.
        log::debug!(
            "Forwarding failure for simulated payment {}: {err}",
            hex::encode(request.payment_hash.0)
        );

        PaymentResult {
            htlc_count: 0,
            payment_outcome: PaymentOutcome::Unknown,
        }
    } else {
        // If we successfully added the htlc, go ahead and remove all the htlcs in the route with successful resolution.
        match remove_htlcs(
            request.nodes.clone(),
            request.route.hops.len() - 1,
            request.source,
            request.route.clone(),
            request.payment_hash,
            true,
            request.clock.clone(),
            request.interceptors,
        )
        .await
        {
            // If we successfully removed the htlcs, we can write the forwarding results to
            // disk. We do not expect this operation to fail and can shutdown if it does.
            Ok(htlcs) => {
                if let Some(w) = request.writer {
                    if let Err(e) =
                        write_forwards(w, htlcs, request.route.clone(), request.nodes.clone()).await
                    {
                        log::error!("Could not write forwards: {e}");
                        request.shutdown.trigger();
                    }
                }
            },
            Err(e) => {
                if e.is_critical() {
                    request.shutdown.trigger();
                }

                log::error!("Could not remove htlcs from channel: {e}.");
            },
        }

        PaymentResult {
            htlc_count: 1,
            payment_outcome: PaymentOutcome::Success,
        }
    };

    if let Err(e) = request.sender.send(Ok(notify_result)) {
        log::error!("Could not notify payment result: {:?}.", e);
    }
}

#[derive(Debug, Serialize)]
struct HtlcForward {
    incoming_amt: u64,
    incoming_expiry: u32,
    #[serde(with = "serializers::serde_system_time")]
    incoming_add_ts: SystemTime,
    #[serde(with = "serializers::serde_system_time")]
    incoming_remove_ts: SystemTime,
    outgoing_amt: u64,
    outgoing_expiry: u32,
    #[serde(with = "serializers::serde_system_time")]
    outgoing_add_ts: SystemTime,
    #[serde(with = "serializers::serde_system_time")]
    outgoing_remove_ts: SystemTime,
    forwarding_node: PublicKey,
    forwarding_alias: String,
    chan_in: u64,
    chan_out: u64,
}

/// Takes a vector of hops and writes their corresponding forwards to disk. We provide both our list of HTLCs that have
/// been timestamped with add/remove time and the original path which has channel and node information so that we
/// don't need to duplicate storage of that information to write it to disk. Will be a no-op if there route was a
/// single hop because we are only recording forwards (one hop payment has no forwards).
async fn write_forwards(
    writer: Arc<Mutex<BatchedWriter>>,
    htlcs: Vec<Htlc>,
    path: Path,
    nodes: Arc<Mutex<HashMap<ShortChannelID, SimulatedChannel>>>,
) -> Result<(), SimulationError> {
    if htlcs.len() <= 1 {
        return Ok(());
    }

    if htlcs.len() != path.hops.len() {
        return Err(SimulationError::SimulatedNetworkError(format!(
            "Route length: {} != htlc count: {}",
            path.hops.len(),
            htlcs.len()
        )));
    }

    // We want to persist the HTLC forwards that we've simulated, and we have a list of individual
    // hops. To combine the incoming/outgoing htlc for each forward, we start at index 1 and look
    // back to the previous htlc to get our incoming details. If this is a single-hop payment,
    // the for loop will never run.
    for i in 1..=htlcs.len() - 1 {
        let incoming_htlc = htlcs[i - 1];
        let outgoing_htlc = htlcs[i];

        let incoming_channel = ShortChannelID::from(path.hops[i - 1].short_channel_id);
        let incoming_node = path.hops[i - 1].pubkey;

        let node_lock = nodes.lock().await;
        let incoming_channel = node_lock.get(&incoming_channel).ok_or_else(|| {
            SimulationError::SimulatedNetworkError(format!(
                "could not find channel: {}",
                incoming_channel
            ))
        })?;

        writer.lock().await.queue(HtlcForward {
            incoming_amt: incoming_htlc.amount_msat,
            incoming_expiry: incoming_htlc.cltv_expiry,
            incoming_add_ts: incoming_htlc.add_ts,
            incoming_remove_ts: incoming_htlc.remove_ts.unwrap(),
            outgoing_amt: outgoing_htlc.amount_msat,
            outgoing_expiry: outgoing_htlc.cltv_expiry,
            outgoing_add_ts: outgoing_htlc.add_ts,
            outgoing_remove_ts: outgoing_htlc.remove_ts.unwrap(),
            forwarding_node: incoming_node,
            forwarding_alias: incoming_channel
                .get_node(&incoming_node)
                .map_err(|_| {
                    SimulationError::SimulatedNetworkError(format!(
                        "could not find node: {}",
                        incoming_node
                    ))
                })?
                .policy
                .alias
                .clone(),
            chan_in: path.hops[i - 1].short_channel_id,
            chan_out: path.hops[i].short_channel_id,
        })?;
    }

    Ok(())
}

/// WrappedLog implements LDK's logging trait so that we can provide pathfinding with a logger that uses our existing
/// logger.
pub struct WrappedLog {}

impl Logger for WrappedLog {
    fn log(&self, record: Record) {
        match record.level {
            Level::Gossip => log::trace!("{}", record.args),
            Level::Trace => log::trace!("{}", record.args),
            Level::Debug => log::debug!("{}", record.args),
            // LDK has quite noisy info logging for pathfinding, so we downgrade their info logging to our debug level.
            Level::Info => log::debug!("{}", record.args),
            Level::Warn => log::warn!("{}", record.args),
            Level::Error => log::error!("{}", record.args),
        }
    }
}

/// UtxoValidator is a mock utxo validator that just returns a fake output with the desired capacity for a channel.
struct UtxoValidator {
    amount_sat: u64,
    script: ScriptBuf,
}

impl UtxoLookup for UtxoValidator {
    fn get_utxo(&self, _genesis_hash: &ChainHash, _short_channel_id: u64) -> UtxoResult {
        UtxoResult::Sync(Ok(TxOut {
            value: self.amount_sat,
            script_pubkey: self.script.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::test_utils::get_random_keypair;
    use bitcoin::secp256k1::PublicKey;
    use lightning::routing::router::Route;
    use mockall::mock;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    /// Creates a test channel policy with its maximum HTLC size set to half of the in flight limit of the channel.
    /// The minimum HTLC size is hardcoded to 2 so that we can fall beneath this value with a 1 msat htlc.
    fn create_test_policy(max_in_flight_msat: u64) -> ChannelPolicy {
        let (_, pk) = get_random_keypair();
        ChannelPolicy {
            pubkey: pk,
            alias: "".to_string(),
            max_htlc_count: 10,
            max_in_flight_msat,
            min_htlc_size_msat: 2,
            max_htlc_size_msat: max_in_flight_msat / 2,
            cltv_expiry_delta: 10,
            base_fee: 1000,
            fee_rate_prop: 5000,
        }
    }

    /// Creates a set of n simulated channels connected in a chain of channels, where the short channel ID of each
    /// channel is its index in the chain of channels and all capacity is on the side of the node that opened the
    /// channel.
    ///
    /// For example if n = 3 it will produce: node_1 -- node_2 -- node_3 -- node_4, connected by channels.
    fn create_simulated_channels(n: u64, capacity_msat: u64) -> Vec<SimulatedChannel> {
        let mut channels: Vec<SimulatedChannel> = vec![];
        let (_, first_node) = get_random_keypair();

        // Create channels in a ring so that we'll get long payment paths.
        let mut node_1 = first_node;
        for i in 0..n {
            // Generate a new random node pubkey.
            let (_, node_2) = get_random_keypair();

            let node_1_to_2 = ChannelPolicy {
                pubkey: node_1,
                alias: node_1.to_string(),
                max_htlc_count: 483,
                max_in_flight_msat: capacity_msat / 2,
                min_htlc_size_msat: 1,
                max_htlc_size_msat: capacity_msat / 2,
                cltv_expiry_delta: 40,
                base_fee: 1000 * i,
                fee_rate_prop: 1500 * i,
            };

            let node_2_to_1 = ChannelPolicy {
                pubkey: node_2,
                alias: node_2.to_string(),
                max_htlc_count: 483,
                max_in_flight_msat: capacity_msat / 2,
                min_htlc_size_msat: 1,
                max_htlc_size_msat: capacity_msat / 2,
                cltv_expiry_delta: 40 + 10 * i as u32,
                base_fee: 2000 * i,
                fee_rate_prop: i,
            };

            channels.push(SimulatedChannel {
                capacity_msat,
                // Unique channel ID per link.
                short_channel_id: ShortChannelID::from(i),
                node_1: ChannelState::new(node_1_to_2, capacity_msat),
                node_2: ChannelState::new(node_2_to_1, 0),
                forward_only: false,
            });

            // Progress source ID to create a chain of nodes.
            node_1 = node_2;
        }

        channels
    }

    macro_rules! assert_channel_balances {
        ($channel_state:expr, $local_balance:expr, $in_flight_len:expr, $in_flight_total:expr) => {
            assert_eq!($channel_state.local_balance_msat, $local_balance);
            assert_eq!($channel_state.in_flight.len(), $in_flight_len);
            assert_eq!($channel_state.in_flight_total(), $in_flight_total);
        };
    }

    /// Tests state updates related to adding and removing HTLCs to a channel.
    #[test]
    fn test_channel_state_transitions() {
        let local_balance = 100_000_000;
        let mut channel_state =
            ChannelState::new(create_test_policy(local_balance / 2), local_balance);

        // Basic sanity check that we Initialize the channel correctly.
        assert_channel_balances!(channel_state, local_balance, 0, 0);

        // Add a few HTLCs to our internal state and assert that balances are as expected. We'll test
        // `check_outgoing_addition` in more detail in another test, so we just assert that we can add the htlc in
        // this test.
        let hash_1 = PaymentHash([1; 32]);
        let htlc_1 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: 1000,
            cltv_expiry: 40,
        };

        assert!(channel_state.add_outgoing_htlc(hash_1, htlc_1).is_ok());
        assert_channel_balances!(
            channel_state,
            local_balance - htlc_1.amount_msat,
            1,
            htlc_1.amount_msat
        );

        // Try to add a htlc with the same payment hash and assert that we fail because we enforce one htlc per hash
        // at present.
        assert!(matches!(
            channel_state.add_outgoing_htlc(hash_1, htlc_1),
            Err(ForwardingError::PaymentHashExists(_))
        ));

        // Add a second, distinct htlc to our in-flight state.
        let hash_2 = PaymentHash([2; 32]);
        let htlc_2 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: 1000,
            cltv_expiry: 40,
        };

        assert!(channel_state.add_outgoing_htlc(hash_2, htlc_2).is_ok());
        assert_channel_balances!(
            channel_state,
            local_balance - htlc_1.amount_msat - htlc_2.amount_msat,
            2,
            htlc_1.amount_msat + htlc_2.amount_msat
        );

        // Remove our second htlc with a failure so that our in-flight drops and we return the balance.
        assert!(channel_state.remove_outgoing_htlc(&hash_2).is_ok());
        channel_state.settle_outgoing_htlc(htlc_2.amount_msat, false);
        assert_channel_balances!(
            channel_state,
            local_balance - htlc_1.amount_msat,
            1,
            htlc_1.amount_msat
        );

        // Try to remove the same htlc and assert that we fail because the htlc can't be found.
        assert!(matches!(
            channel_state.remove_outgoing_htlc(&hash_2),
            Err(ForwardingError::PaymentHashNotFound(_))
        ));

        // Finally, remove our original htlc with success and assert that our local balance is accordingly updated.
        assert!(channel_state.remove_outgoing_htlc(&hash_1).is_ok());
        channel_state.settle_outgoing_htlc(htlc_1.amount_msat, true);
        assert_channel_balances!(channel_state, local_balance - htlc_1.amount_msat, 0, 0);
    }

    /// Tests policy checks applied when forwarding a htlc over a channel.
    #[test]
    fn test_htlc_forward() {
        let local_balance = 140_000;
        let channel_state = ChannelState::new(create_test_policy(local_balance / 2), local_balance);

        // CLTV delta insufficient (one less than required).
        assert!(matches!(
            channel_state.check_htlc_forward(channel_state.policy.cltv_expiry_delta - 1, 0, 0),
            Err(ForwardingError::InsufficientCltvDelta(_, _))
        ));

        // Test insufficient fee.
        let htlc_amount = 1000;
        let htlc_fee = channel_state.policy.base_fee
            + (channel_state.policy.fee_rate_prop * htlc_amount) / 1e6 as u64;

        assert!(matches!(
            channel_state.check_htlc_forward(
                channel_state.policy.cltv_expiry_delta,
                htlc_amount,
                htlc_fee - 1
            ),
            Err(ForwardingError::InsufficientFee(_, _, _, _))
        ));

        // Test exact and over-estimation of required policy.
        assert!(channel_state
            .check_htlc_forward(
                channel_state.policy.cltv_expiry_delta,
                htlc_amount,
                htlc_fee,
            )
            .is_ok());

        assert!(channel_state
            .check_htlc_forward(
                channel_state.policy.cltv_expiry_delta * 2,
                htlc_amount,
                htlc_fee * 3
            )
            .is_ok());
    }

    /// Test addition of outgoing htlc to local state.
    #[test]
    fn test_check_outgoing_addition() {
        // Create test channel with low local liquidity so that we run into failures.
        let local_balance = 100_000;
        let mut channel_state =
            ChannelState::new(create_test_policy(local_balance / 2), local_balance);

        let mut htlc = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: channel_state.policy.max_htlc_size_msat + 1,
            cltv_expiry: channel_state.policy.cltv_expiry_delta,
        };
        // HTLC maximum size exceeded.
        assert!(matches!(
            channel_state.check_outgoing_addition(&htlc),
            Err(ForwardingError::MoreThanMaximum(_, _))
        ));

        // Beneath HTLC minimum size.
        htlc.amount_msat = channel_state.policy.min_htlc_size_msat - 1;
        assert!(matches!(
            channel_state.check_outgoing_addition(&htlc),
            Err(ForwardingError::LessThanMinimum(_, _))
        ));

        // Add two large htlcs so that we will start to run into our in-flight total amount limit.
        let hash_1 = PaymentHash([1; 32]);
        let htlc_1 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: channel_state.policy.max_in_flight_msat / 2,
            cltv_expiry: channel_state.policy.cltv_expiry_delta,
        };

        assert!(channel_state.check_outgoing_addition(&htlc_1).is_ok());
        assert!(channel_state.add_outgoing_htlc(hash_1, htlc_1).is_ok());

        let hash_2 = PaymentHash([2; 32]);
        let htlc_2 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: channel_state.policy.max_in_flight_msat / 2,
            cltv_expiry: channel_state.policy.cltv_expiry_delta,
        };

        assert!(channel_state.check_outgoing_addition(&htlc_2).is_ok());
        assert!(channel_state.add_outgoing_htlc(hash_2, htlc_2).is_ok());

        // Now, assert that we can't add even our smallest htlc size, because we're hit our in-flight amount limit.
        htlc.amount_msat = channel_state.policy.min_htlc_size_msat;
        assert!(matches!(
            channel_state.check_outgoing_addition(&htlc),
            Err(ForwardingError::ExceedsInFlightTotal(_, _))
        ));

        // Resolve both of the htlcs successfully so that the local liquidity is no longer available.
        assert!(channel_state.remove_outgoing_htlc(&hash_1).is_ok());
        channel_state.settle_outgoing_htlc(htlc_1.amount_msat, true);

        assert!(channel_state.remove_outgoing_htlc(&hash_2).is_ok());
        channel_state.settle_outgoing_htlc(htlc_2.amount_msat, true);

        // Now we're going to add many htlcs so that we hit our in-flight count limit (unique payment hash per htlc).
        for i in 0..channel_state.policy.max_htlc_count {
            let hash = PaymentHash([i.try_into().unwrap(); 32]);
            assert!(channel_state.check_outgoing_addition(&htlc).is_ok());
            assert!(channel_state.add_outgoing_htlc(hash, htlc).is_ok());
        }

        // Try to add one more htlc and we should be rejected.
        let htlc_3 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: channel_state.policy.min_htlc_size_msat,
            cltv_expiry: channel_state.policy.cltv_expiry_delta,
        };

        assert!(matches!(
            channel_state.check_outgoing_addition(&htlc_3),
            Err(ForwardingError::ExceedsInFlightCount(_, _))
        ));

        // Resolve all in-flight htlcs.
        for i in 0..channel_state.policy.max_htlc_count {
            let hash = PaymentHash([i.try_into().unwrap(); 32]);
            assert!(channel_state.remove_outgoing_htlc(&hash).is_ok());
            channel_state.settle_outgoing_htlc(htlc.amount_msat, true)
        }

        // Add and settle another htlc to move more liquidity away from our local balance.
        let hash_4 = PaymentHash([1; 32]);
        let htlc_4 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: channel_state.policy.max_htlc_size_msat,
            cltv_expiry: channel_state.policy.cltv_expiry_delta,
        };
        assert!(channel_state.check_outgoing_addition(&htlc_4).is_ok());
        assert!(channel_state.add_outgoing_htlc(hash_4, htlc_4).is_ok());
        assert!(channel_state.remove_outgoing_htlc(&hash_4).is_ok());
        channel_state.settle_outgoing_htlc(htlc_4.amount_msat, true);

        // Finally, assert that we don't have enough balance to forward our largest possible htlc (because of all the
        // htlcs that we've settled) and assert that we fail to a large htlc. The balance assertion here is just a
        // sanity check for the test, which will fail if we change the amounts settled/failed in the test.
        assert!(channel_state.local_balance_msat < channel_state.policy.max_htlc_size_msat);
        assert!(matches!(
            channel_state.check_outgoing_addition(&htlc_4),
            Err(ForwardingError::InsufficientBalance(_, _))
        ));
    }

    /// Tests basic functionality of a `SimulatedChannel` but does no endeavor to test the underlying
    /// `ChannelState`, as this is covered elsewhere in our tests.
    #[test]
    fn test_simulated_channel() {
        // Create a test channel with all balance available to node 1 as local liquidity, and none for node_2 to begin
        // with.
        let capacity_msat = 500_000_000;
        let node_1 = ChannelState::new(create_test_policy(capacity_msat / 2), capacity_msat);
        let node_2 = ChannelState::new(create_test_policy(capacity_msat / 2), 0);

        let mut simulated_channel = SimulatedChannel {
            capacity_msat,
            short_channel_id: ShortChannelID::from(123),
            node_1: node_1.clone(),
            node_2: node_2.clone(),
            forward_only: false,
        };

        // Assert that we're not able to send a htlc over node_2 -> node_1 (no liquidity).
        let hash_1 = PaymentHash([1; 32]);
        let htlc_1 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: node_2.policy.min_htlc_size_msat,
            cltv_expiry: node_1.policy.cltv_expiry_delta,
        };

        assert!(matches!(
            simulated_channel.add_htlc(&node_2.policy.pubkey, hash_1, htlc_1),
            Err(ForwardingError::InsufficientBalance(_, _))
        ));

        // Assert that we can send a htlc over node_1 -> node_2.
        let hash_2 = PaymentHash([1; 32]);
        let htlc_2 = Htlc {
            add_ts: SystemTime::UNIX_EPOCH,
            remove_ts: None,
            amount_msat: node_1.policy.max_htlc_size_msat,
            cltv_expiry: node_2.policy.cltv_expiry_delta,
        };
        assert!(simulated_channel
            .add_htlc(&node_1.policy.pubkey, hash_2, htlc_2)
            .is_ok());

        // Settle the htlc and then assert that we can send from node_2 -> node_2 because the balance has been shifted
        // across channels.
        assert!(simulated_channel
            .remove_htlc(&node_1.policy.pubkey, &hash_1, true, SystemTime::now())
            .is_ok());

        assert!(simulated_channel
            .add_htlc(&node_2.policy.pubkey, hash_2, htlc_2)
            .is_ok());

        // Finally, try to add/remove htlcs for a pubkey that is not participating in the channel and assert that we
        // fail.
        let (_, pk) = get_random_keypair();
        assert!(matches!(
            simulated_channel.add_htlc(&pk, hash_2, htlc_2),
            Err(ForwardingError::NodeNotFound(_))
        ));

        assert!(matches!(
            simulated_channel.remove_htlc(&pk, &hash_2, true, SystemTime::now()),
            Err(ForwardingError::NodeNotFound(_))
        ));
    }

    mock! {
        Network{}

        #[async_trait]
        impl SimNetwork for Network{
            fn dispatch_payment(
                &mut self,
                source: PublicKey,
                route: Route,
                payment_hash: PaymentHash,
                sender: Sender<Result<PaymentResult, LightningError>>,
            );

            async fn lookup_node(&self, node: &PublicKey) -> Result<(NodeInfo, Vec<u64>), LightningError>;
        }
    }

    /// Tests the functionality of a `SimNode`, mocking out the `SimNetwork` that is responsible for payment
    /// propagation to isolate testing to just the implementation of `LightningNode`.
    #[tokio::test]
    async fn test_simulated_node() {
        // Mock out our network and create a routing graph with 5 hops.
        let mock = MockNetwork::new();
        let sim_network = Arc::new(Mutex::new(mock));
        let channels = create_simulated_channels(5, 300000000);
        let clock = Arc::new(SystemClock {});

        let graph = populate_network_graph(channels.clone(), clock).unwrap();

        // Create a simulated node for the first channel in our network.
        let info = node_info(channels[0].node_1.policy.pubkey, "".to_string());
        let mut node = SimNode::new(info, sim_network.clone(), Arc::new(graph));

        // Prime mock to return node info from lookup and assert that we get the pubkey we're expecting.
        let lookup_pk = channels[3].node_1.policy.pubkey;
        let lookup_alias = channels[3].node_1.policy.alias.clone();
        let expected_info = node_info(lookup_pk, lookup_alias.clone());
        sim_network
            .lock()
            .await
            .expect_lookup_node()
            .returning(move |_| Ok((node_info(lookup_pk, lookup_alias.clone()), vec![1, 2, 3])));

        // Assert that we get three channels from the mock.
        let actual_info = node.get_node_info(&lookup_pk).await.unwrap();
        assert_eq!(expected_info, actual_info);
        assert_eq!(node.list_channels().await.unwrap().len(), 3);

        // Next, we're going to test handling of in-flight payments. To do this, we'll mock out calls to our dispatch
        // function to send different results depending on the destination.
        let dest_1 = channels[2].node_1.policy.pubkey;
        let dest_2 = channels[4].node_1.policy.pubkey;

        sim_network
            .lock()
            .await
            .expect_dispatch_payment()
            .returning(
                move |_, route: Route, _, sender: Sender<Result<PaymentResult, LightningError>>| {
                    // If we've reached dispatch, we must have at least one path, grab the last hop to match the
                    // receiver.
                    let receiver = route.paths[0].hops.last().unwrap().pubkey;
                    let result = if receiver == dest_1 {
                        PaymentResult {
                            htlc_count: 2,
                            payment_outcome: PaymentOutcome::Success,
                        }
                    } else if receiver == dest_2 {
                        PaymentResult {
                            htlc_count: 0,
                            payment_outcome: PaymentOutcome::InsufficientBalance,
                        }
                    } else {
                        panic!("unknown mocked receiver");
                    };

                    sender.send(Ok(result)).unwrap();
                },
            );

        // Dispatch payments to different destinations and assert that our track payment results are as expected.
        let hash_1 = node.send_payment(dest_1, 10_000).await.unwrap();
        let hash_2 = node.send_payment(dest_2, 15_000).await.unwrap();

        let (_, shutdown_listener) = triggered::trigger();

        let result_1 = node
            .track_payment(&hash_1, shutdown_listener.clone())
            .await
            .unwrap();
        assert!(matches!(result_1.payment_outcome, PaymentOutcome::Success));

        let result_2 = node
            .track_payment(&hash_2, shutdown_listener.clone())
            .await
            .unwrap();
        assert!(matches!(
            result_2.payment_outcome,
            PaymentOutcome::InsufficientBalance
        ));
    }

    /// Contains elements required to test dispatch_payment functionality.
    struct DispatchPaymentTestKit<'a> {
        graph: SimGraph,
        nodes: Vec<PublicKey>,
        routing_graph: NetworkGraph<&'a WrappedLog>,
        shutdown: triggered::Trigger,
    }

    impl<'a> DispatchPaymentTestKit<'a> {
        /// Creates a test graph with a set of nodes connected by three channels, with all the capacity of the channel
        /// on the side of the first node. For example, if called with capacity = 100 it will set up the following
        /// network:
        /// Alice (100) --- (0) Bob (100) --- (0) Carol (100) --- (0) Dave
        ///
        /// The nodes pubkeys in this chain of channels are provided in-order for easy access.
        async fn new(capacity: u64) -> Self {
            let (shutdown, listener) = triggered::trigger();
            let channels = create_simulated_channels(3, capacity);

            // Collect pubkeys in-order, pushing the last node on separately because they don't have an outgoing
            // channel (they are not node_1 in any channel, only node_2).
            let mut nodes = channels
                .iter()
                .map(|c| c.node_1.policy.pubkey)
                .collect::<Vec<PublicKey>>();
            nodes.push(channels.last().unwrap().node_2.policy.pubkey);

            let clock = Arc::new(SystemClock {});
            let kit = DispatchPaymentTestKit {
                graph: SimGraph::new(
                    channels.clone(),
                    clock.clone(),
                    None,
                    vec![],
                    listener.clone(),
                    shutdown.clone(),
                )
                .expect("could not create test graph"),
                nodes,
                routing_graph: populate_network_graph(channels, clock).unwrap(),
                shutdown,
            };

            // Assert that our channel balance is all on the side of the channel opener when we start up.
            assert_eq!(
                kit.channel_balances().await,
                vec![(capacity, 0), (capacity, 0), (capacity, 0)]
            );

            kit
        }

        /// Returns a vector of local/remote channel balances for channels in the network.
        async fn channel_balances(&self) -> Vec<(u64, u64)> {
            let mut balances = vec![];

            // We can't iterate through our hashmap of channels in-order, so we take advantage of our short channel id
            // being the index in our chain of channels. This allows us to look up channels in-order.
            let chan_count = self.graph.channels.lock().await.len();

            for i in 0..chan_count {
                let chan_lock = self.graph.channels.lock().await;
                let channel = chan_lock.get(&ShortChannelID::from(i as u64)).unwrap();

                // Take advantage of our test setup, which always makes node_1 the channel initiator to get our
                // "in order" balances for the chain of channels.
                balances.push((
                    channel.node_1.local_balance_msat,
                    channel.node_2.local_balance_msat,
                ));
            }

            balances
        }

        // Sends a test payment from source to destination and waits for the payment to complete, returning the route
        // used.
        async fn send_test_payemnt(
            &mut self,
            source: PublicKey,
            dest: PublicKey,
            amt: u64,
        ) -> Route {
            let route = find_payment_route(&source, dest, amt, &self.routing_graph).unwrap();

            let (sender, receiver) = oneshot::channel();
            self.graph
                .dispatch_payment(source, route.clone(), PaymentHash([1; 32]), sender);

            // Assert that we receive from the channel or fail.
            assert!(timeout(Duration::from_millis(10), receiver).await.is_ok());

            route
        }

        // Sets the balance on the channel to the tuple provided, used to arrange liquidity for testing.
        async fn set_channel_balance(&mut self, scid: &ShortChannelID, balance: (u64, u64)) {
            let mut channels_lock = self.graph.channels.lock().await;
            let channel = channels_lock.get_mut(scid).unwrap();

            channel.node_1.local_balance_msat = balance.0;
            channel.node_2.local_balance_msat = balance.1;

            assert!(channel.sanity_check().is_ok());
        }
    }

    /// Tests dispatch of a successfully settled payment across a test network of simulated channels:
    /// Alice --- Bob --- Carol --- Dave
    #[tokio::test]
    async fn test_successful_dispatch() {
        let chan_capacity = 500_000_000;
        let mut test_kit = DispatchPaymentTestKit::new(chan_capacity).await;

        // Send a payment that should succeed from Alice -> Dave.
        let mut amt = 20_000;
        let route = test_kit
            .send_test_payemnt(test_kit.nodes[0], test_kit.nodes[3], amt)
            .await;

        let route_total = amt + route.get_total_fees();
        let hop_1_amt = amt + route.paths[0].hops[1].fee_msat;

        // The sending node should have pushed the amount + total fee to the intermediary.
        let alice_to_bob = (chan_capacity - route_total, route_total);
        // The middle hop should include fees for the outgoing link.
        let mut bob_to_carol = (chan_capacity - hop_1_amt, hop_1_amt);
        // The receiving node should have the payment amount pushed to them.
        let carol_to_dave = (chan_capacity - amt, amt);

        let mut expected_balances = vec![alice_to_bob, bob_to_carol, carol_to_dave];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Next, we'll test the case where a payment fails on the first hop. This is an edge case in our state
        // machine, so we want to specifically hit it. To do this, we'll try to send double the amount that we just
        // pushed to Dave back to Bob, expecting a failure on Dave's outgoing link due to insufficient liquidity.
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[3], test_kit.nodes[1], amt * 2)
            .await;
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Now, test a successful single-hop payment from Bob -> Carol. We'll do this twice, so that we can drain all
        // the liquidity on Bob's side (to prepare for a multi-hop failure test). Our pathfinding only allows us to
        // use 50% of the channel's capacity, so we need to do two payments.
        amt = bob_to_carol.0 / 2;
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[1], test_kit.nodes[2], amt)
            .await;

        bob_to_carol = (bob_to_carol.0 / 2, bob_to_carol.1 + amt);
        expected_balances = vec![alice_to_bob, bob_to_carol, carol_to_dave];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // When we push this amount a second time, all the liquidity should be moved to Carol's end.
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[1], test_kit.nodes[2], amt)
            .await;
        bob_to_carol = (0, chan_capacity);
        expected_balances = vec![alice_to_bob, bob_to_carol, carol_to_dave];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Finally, we'll test a multi-hop failure by trying to send from Alice -> Dave. Since Bob's liquidity is
        // drained, we expect a failure and unchanged balances along the route.
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[0], test_kit.nodes[3], 20_000)
            .await;
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        test_kit.shutdown.trigger();
        test_kit.graph.wait_for_shutdown().await;
    }

    /// Tests successful dispatch of a multi-hop payment.
    #[tokio::test]
    async fn test_successful_multi_hop() {
        let chan_capacity = 500_000_000;
        let mut test_kit = DispatchPaymentTestKit::new(chan_capacity).await;

        // Send a payment that should succeed from Alice -> Dave.
        let amt = 20_000;
        let route = test_kit
            .send_test_payemnt(test_kit.nodes[0], test_kit.nodes[3], amt)
            .await;

        let route_total = amt + route.get_total_fees();
        let hop_1_amt = amt + route.paths[0].hops[1].fee_msat;

        let expected_balances = vec![
            // The sending node should have pushed the amount + total fee to the intermediary.
            (chan_capacity - route_total, route_total),
            // The middle hop should include fees for the outgoing link.
            (chan_capacity - hop_1_amt, hop_1_amt),
            // The receiving node should have the payment amount pushed to them.
            (chan_capacity - amt, amt),
        ];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        test_kit.shutdown.trigger();
        test_kit.graph.wait_for_shutdown().await;
    }

    /// Tests success and failure for single hop payments, which are an edge case in our state machine.
    #[tokio::test]
    async fn test_single_hop_payments() {
        let chan_capacity = 500_000_000;
        let mut test_kit = DispatchPaymentTestKit::new(chan_capacity).await;

        // Send a single hop payment from Alice -> Bob, it will succeed because Alice has all the liquidity.
        let amt = 150_000;
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[0], test_kit.nodes[1], amt)
            .await;

        let expected_balances = vec![
            (chan_capacity - amt, amt),
            (chan_capacity, 0),
            (chan_capacity, 0),
        ];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Send a single hop payment from Dave -> Carol that will fail due to lack of liquidity, balances should be
        // unchanged.
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[3], test_kit.nodes[2], amt)
            .await;

        assert_eq!(test_kit.channel_balances().await, expected_balances);

        test_kit.shutdown.trigger();
        test_kit.graph.wait_for_shutdown().await;
    }

    /// Tests failing back of multi-hop payments at various failure indexes.
    #[tokio::test]
    async fn test_multi_hop_faiulre() {
        let chan_capacity = 500_000_000;
        let mut test_kit = DispatchPaymentTestKit::new(chan_capacity).await;

        // Drain liquidity between Bob and Carol to force failures on Bob's outgoing linke.
        test_kit
            .set_channel_balance(&ShortChannelID::from(1), (0, chan_capacity))
            .await;

        let mut expected_balances =
            vec![(chan_capacity, 0), (0, chan_capacity), (chan_capacity, 0)];
        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Send a payment from Alice -> Dave which we expect to fail leaving balances unaffected.
        let amt = 150_000;
        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[0], test_kit.nodes[3], amt)
            .await;

        assert_eq!(test_kit.channel_balances().await, expected_balances);

        // Push liquidity to Dave so that we can send a payment which will fail on Bob's outgoing link, leaving
        // balances unaffected.
        expected_balances[2] = (0, chan_capacity);
        test_kit
            .set_channel_balance(&ShortChannelID::from(2), (0, chan_capacity))
            .await;

        let _ = test_kit
            .send_test_payemnt(test_kit.nodes[3], test_kit.nodes[0], amt)
            .await;

        assert_eq!(test_kit.channel_balances().await, expected_balances);

        test_kit.shutdown.trigger();
        test_kit.graph.wait_for_shutdown().await;
    }
}
