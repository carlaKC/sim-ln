use async_trait::async_trait;
use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use lightning::ln::features::NodeFeatures;
use lightning::ln::msgs::LightningError as LdkError;
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::gossip::NetworkGraph;
use lightning::routing::router::{find_route, Payee, PaymentParameters, Route, RouteParameters};
use lightning::routing::scoring::{
    ProbabilisticScorer, ProbabilisticScoringDecayParameters, ProbabilisticScoringFeeParameters,
};
use lightning::util::logger::{Level, Logger, Record};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use triggered::Listener;

use crate::{LightningError, LightningNode, NodeInfo, PaymentOutcome, PaymentResult};

#[derive(Debug)]
/// ForwardingError represents the various errors that we can run into when forwarding payments in a simulated network.
/// Since we're not using real lightning nodes, these errors are not obfuscated and can be propagated to the sending
/// node and used for analysis.
pub enum ForwardingError {
    /// Zero amount htlcs are in valid in the protocol.
    ZeroAmountHtlc,
    /// The outgoing channel id was not found in the network graph.
    ChannelNotFound(u64),
    /// The node pubkey provided was not associated with the channel in the network graph.
    NodeNotFound(PublicKey),
    /// The channel has already forwarded a HTLC with the payment hash provided (to be removed when MPP support is
    /// added).
    PaymentHashExists(PaymentHash),
    /// A htlc with the payment hash provided could not be found to resolve.
    PaymentHashNotFound(PaymentHash),
    /// The forwarding node did not have sufficient outgoing balance to forward the htlc (htlc amount / balance).
    InsufficientBalance(u64, u64),
    /// The htlc forwarded is less than the channel's advertised minimum htlc amount (htlc amount / minimum).
    LessThanMinimum(u64, u64),
    /// The htlc forwarded is more than the chanenl's advertised maximum htlc amount (htlc amount / maximum).
    MoreThanMaximum(u64, u64),
    /// The channel has reached its maximum allowable number of htlcs in flight (total in flight / maximim).
    ExceedsInFlightCount(u64, u64),
    /// The forwarded htlc's amount would push the channel over its maximum allowable in flight total
    /// (htlc amount / total in flight / maximum).
    ExceedsInFlightTotal(u64, u64, u64),
    /// The forwarded htlc's cltv expiry exceeds the maximum value used to express block heights in bitcoin.
    ExpiryInSeconds(u32),
    /// The forwarded htlc has insufficient cltv delta for the channel's minimum delta (cltv delta / minimum).
    InsufficientCltvDelta(u32, u32),
    /// The forwarded htlc has insufficient fee for the channel's policy (fee / base fee / prop fee / expected fee).
    InsufficientFee(u64, u64, u64, u64),
    /// Sanity check on channel balances failed (capacity / node_1 balance / node_2 balance).
    SanityCheckFailed(u64, u64, u64),
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
                | ForwardingError::SanityCheckFailed(_, _, _)
        )
    }
}

impl Display for ForwardingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardingError::ZeroAmountHtlc => write!(f, "zero amount htlc"),
            ForwardingError::ChannelNotFound(chan_id) => write!(f, "channel {chan_id} not found"),
			ForwardingError::NodeNotFound(node) => write!(f, "node: {node} not found"),
            ForwardingError::PaymentHashExists(hash) => write!(f, "payment hash {} already forwarded", hex::encode(hash.0)),
            ForwardingError::PaymentHashNotFound(hash) => write!(f, "payment hash {} not found", hex::encode(hash.0)),
			ForwardingError::InsufficientBalance(htlc_amt, local_bal) => write!(f, "local balance: {local_bal} insufficient for htlc: {htlc_amt}"),
			ForwardingError::LessThanMinimum(htlc_amt,min_amt ) => write!(f, "channel minimum: {min_amt} > htlc: {htlc_amt}"),
			ForwardingError::MoreThanMaximum(htlc_amt,max_amt )=> write!(f,"channel maximum: {max_amt} < htlc: {htlc_amt}"),
			ForwardingError::ExceedsInFlightCount(in_flight, max_in_flight ) => write!(f, "maximum in flight count: {max_in_flight} reached with {in_flight} htlcs"),
			ForwardingError::ExceedsInFlightTotal(htlc_amt, in_flight_amt, max_in_flight) => write!(f, "maximum in flight amount: {max_in_flight} with {in_flight_amt} in flight exceeded by htlc: {htlc_amt}"),
			ForwardingError::ExpiryInSeconds(cltv_delta) => write!(f, "cltv: {cltv_delta} expressed in seconds"),
			ForwardingError::InsufficientCltvDelta(cltv_delta, min_delta ) => write!(f, "minimum cltv delta: {min_delta} not met by: {cltv_delta}"),
			ForwardingError::InsufficientFee(htlc_fee, base_fee, prop_fee, expected_fee) => write!(f,"expected fee: {expected_fee} (base: {base_fee}, prop: {prop_fee}), got: {htlc_fee}"),
			ForwardingError::SanityCheckFailed(capacity,node_1_balance ,node_2_balance ) => write!(f, "sanity check failed for capacity: {capacity}, node_1: {node_1_balance}, node_2: {node_2_balance}"),
        }
    }
}

#[derive(Copy, Clone)]
struct Htlc {
    hash: PaymentHash,
    amount_msat: u64,
    cltv_expiry: u32,
}

#[derive(Clone)]
/// Represents one node in the channel's forwarding policy and restrictions. Note that this doesn't directly map to
/// a single concept in the protocol, a few things have been combined for the sake of simplicity.
pub struct ChannelPolicy {
    pub pubkey: PublicKey,
    pub max_htlc_count: u64,
    pub max_in_flight_msat: u64,
    pub min_htlc_size_msat: u64,
    pub max_htlc_size_msat: u64,
    pub cltv_expiry_delta: u32,
    pub base_fee: u64,
    pub fee_rate_prop: u64,
}

/// The internal state of one side of a simulated channel.
#[derive(Clone)]
struct ChannelState {
    local_balance_msat: u64,
    in_flight: HashMap<PaymentHash, Htlc>,
    policy: ChannelPolicy,
}

impl ChannelState {
    fn new(policy: ChannelPolicy, capacity_msat: u64) -> Self {
        ChannelState {
            local_balance_msat: capacity_msat / 2,
            in_flight: HashMap::new(),
            policy,
        }
    }

    fn in_flight_total(&self) -> u64 {
        self.in_flight
            .iter()
            .fold(0, |sum, val| sum + val.1.amount_msat)
    }

    fn check_forward(&self, cltv_delta: u32, amt: u64, fee: u64) -> Result<(), ForwardingError> {
        if cltv_delta < self.policy.cltv_expiry_delta {
            return Err(ForwardingError::InsufficientCltvDelta(
                cltv_delta,
                self.policy.cltv_expiry_delta,
            ));
        }

        // As u64 will round expected fee down to nearest msat.
        let expected_fee = (self.policy.base_fee as f64
            + ((self.policy.fee_rate_prop as f64 * amt as f64) / 1000000.0))
            as u64;
        if fee < expected_fee {
            return Err(ForwardingError::InsufficientFee(
                fee,
                self.policy.base_fee,
                self.policy.fee_rate_prop,
                expected_fee,
            ));
        }

        Ok(())
    }

    fn check_policy(&self, htlc: &Htlc) -> Result<(), ForwardingError> {
        if htlc.amount_msat > self.local_balance_msat {
            return Err(ForwardingError::InsufficientBalance(
                htlc.amount_msat,
                self.local_balance_msat,
            ));
        }

        if htlc.amount_msat < self.policy.min_htlc_size_msat {
            return Err(ForwardingError::LessThanMinimum(
                htlc.amount_msat,
                self.policy.min_htlc_size_msat,
            ));
        }

        if htlc.amount_msat > self.policy.max_htlc_size_msat {
            return Err(ForwardingError::MoreThanMaximum(
                htlc.amount_msat,
                self.policy.max_htlc_size_msat,
            ));
        }

        if self.in_flight.len() as u64 + 1 > self.policy.max_htlc_count {
            return Err(ForwardingError::ExceedsInFlightCount(
                self.in_flight.len() as u64,
                self.policy.max_htlc_count,
            ));
        }

        if self.in_flight_total() + htlc.amount_msat > self.policy.max_in_flight_msat {
            return Err(ForwardingError::ExceedsInFlightTotal(
                htlc.amount_msat,
                self.in_flight_total(),
                self.policy.max_in_flight_msat,
            ));
        }

        if htlc.cltv_expiry > 500000000 {
            return Err(ForwardingError::ExpiryInSeconds(htlc.cltv_expiry));
        }

        Ok(())
    }

    fn add_outgoing_htlc(&mut self, htlc: Htlc) -> Result<(), ForwardingError> {
        self.check_policy(&htlc)?;

        match self.in_flight.get(&htlc.hash) {
            Some(_) => Err(ForwardingError::PaymentHashExists(htlc.hash)),
            None => {
                self.local_balance_msat -= htlc.amount_msat;
                self.in_flight.insert(htlc.hash, htlc);
                Ok(())
            }
        }
    }

    fn remove_outgoing_htlc(
        &mut self,
        hash: PaymentHash,
        success: bool,
    ) -> Result<Htlc, ForwardingError> {
        match self.in_flight.remove(&hash) {
            Some(v) => {
                // If the HTLC failed, pending balance returns to local balance.
                if !success {
                    self.local_balance_msat += v.amount_msat
                }

                Ok(v)
            }
            None => Err(ForwardingError::PaymentHashNotFound(hash)),
        }
    }
}

#[derive(Clone)]
pub struct SimulatedChannel {
    capacity_msat: u64,
    short_channel_id: u64,
    node_1: ChannelState,
    node_2: ChannelState,
}

impl SimulatedChannel {
    pub fn new(
        capacity_msat: u64,
        short_channel_id: u64,
        node_1: ChannelPolicy,
        node_2: ChannelPolicy,
    ) -> Self {
        SimulatedChannel {
            capacity_msat,
            short_channel_id,
            node_1: ChannelState::new(node_1, capacity_msat),
            node_2: ChannelState::new(node_2, capacity_msat),
        }
    }
}

impl SimulatedChannel {
    /// Adds a htlc to the appropriate side of the simulated channel, checking its policy and balance are okay.
    fn add_htlc(&mut self, node: PublicKey, htlc: Htlc) -> Result<(), ForwardingError> {
        if htlc.amount_msat == 0 {
            return Err(ForwardingError::ZeroAmountHtlc);
        }

        if node == self.node_1.policy.pubkey {
            self.node_1.add_outgoing_htlc(htlc)?;
            return self.sanity_check();
        }

        if node == self.node_2.policy.pubkey {
            self.node_2.add_outgoing_htlc(htlc)?;
            return self.sanity_check();
        }

        Err(ForwardingError::NodeNotFound(node))
    }

    /// Performs a sanity check on the total balances in a channel. Note that we do not currently include on-chain
    /// fees or reserve so these values should exactly match.
    fn sanity_check(&self) -> Result<(), ForwardingError> {
        let node_1_total = self.node_1.local_balance_msat + self.node_1.in_flight_total();
        let node_2_total = self.node_2.local_balance_msat + self.node_2.in_flight_total();

        if node_1_total + node_2_total != self.capacity_msat {
            return Err(ForwardingError::SanityCheckFailed(
                self.capacity_msat,
                node_1_total,
                node_2_total,
            ));
        }

        Ok(())
    }

    /// Removes a htlc from the appropriate size of the simulated channel, settling balances across channel sides
    /// based on the success of the htlc.
    fn remove_htlc(
        &mut self,
        incoming_node: PublicKey,
        hash: PaymentHash,
        success: bool,
    ) -> Result<(), ForwardingError> {
        // TODO: macro for this?
        if incoming_node == self.node_1.policy.pubkey {
            let htlc = self.node_1.remove_outgoing_htlc(hash, success)?;

            // If the HTLC was settled, its amount is transferred to the remote party's local balance.
            // If it was failed, the above removal has already dealt with balance management.
            if success {
                self.node_2.local_balance_msat += htlc.amount_msat
            }

            return self.sanity_check();
        }

        if incoming_node == self.node_2.policy.pubkey {
            let htlc = self.node_2.remove_outgoing_htlc(hash, success)?;

            // If the HTLC was settled, its amount is transferred to the remote party's local balance.
            // If it was failed, the above removal has already dealt with balance management.
            if success {
                self.node_1.local_balance_msat += htlc.amount_msat
            }

            return self.sanity_check();
        }

        Err(ForwardingError::NodeNotFound(incoming_node))
    }

    /// Checks a htlc forward against the outgoing policy of the node provided.
    fn check_htlc_forward(
        &self,
        node: PublicKey,
        cltv_delta: u32,
        amount_msat: u64,
        fee_msat: u64,
    ) -> Result<(), ForwardingError> {
        if node == self.node_1.policy.pubkey {
            return self.node_1.check_forward(cltv_delta, amount_msat, fee_msat);
        }

        if node == self.node_2.policy.pubkey {
            return self.node_2.check_forward(cltv_delta, amount_msat, fee_msat);
        }

        Err(ForwardingError::NodeNotFound(node))
    }
}

#[async_trait]
trait SimNetwork: Send + Sync {
    fn dispatch_payment(
        &mut self,
        source: PublicKey,
        route: Route,
        preimage: PaymentPreimage,
        sender: Sender<Result<PaymentResult, LightningError>>,
    );

    async fn lookup_node(&self, node: &PublicKey) -> Result<(NodeInfo, Vec<u64>), LightningError>;
}

/// A wrapper struct used to implement the LightningNode trait (can be thought of as "the" lightning node). Passes
/// all functionality through to a coordinating simulation network. This implementation contains both the  SimNetwork
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
    pub fn new(
        pubkey: PublicKey,
        payment_network: Arc<Mutex<T>>,
        pathfinding_graph: Arc<NetworkGraph<&'a WrappedLog>>,
    ) -> Self {
        SimNode {
            info: node_info(pubkey),
            network: payment_network,
            in_flight: HashMap::new(),
            pathfinding_graph,
        }
    }
}

/// Produces the node info for a mocked node, filling in the features that the simulator requires.
fn node_info(pk: PublicKey) -> NodeInfo {
    // Set any features that the simulator requires here.
    let mut features = NodeFeatures::empty();
    features.set_keysend_optional();

    NodeInfo {
        pubkey: pk,
        alias: "".to_string(), // TODO: store alias?
        features,
    }
}

/// Uses LDK's pathfinding algorithm with default parameters to find a path from source to destination.
fn find_payment_route(
    source: PublicKey,
    dest: PublicKey,
    amount_msat: u64,
    pathfinding_graph: &NetworkGraph<&WrappedLog>,
) -> Result<Route, LdkError> {
    let params = ProbabilisticScoringDecayParameters::default();
    let scorer = ProbabilisticScorer::new(params, pathfinding_graph, &WrappedLog {});

    find_route(
        &ldk_pubkey(source),
        &RouteParameters {
            payment_params: PaymentParameters {
                payee: Payee::Clear {
                    node_id: ldk_pubkey(dest),
                    route_hints: Vec::new(),
                    features: None,
                    final_cltv_expiry_delta: 0,
                },
                expiry_time: None,
                max_total_cltv_expiry_delta: u32::MAX,
                // TODO: set non-zero value to support MPP.
                max_path_count: 1,
                // Allow sending htlcs up to 50% of the channel's capacity.
                max_channel_saturation_power_of_half: 1,
                previously_failed_channels: Vec::new(),
            },
            final_value_msat: amount_msat,
            max_total_routing_fee_msat: None,
        },
        pathfinding_graph,
        None,
        &WrappedLog {},
        &scorer,
        &ProbabilisticScoringFeeParameters::default(),
        &[0; 32],
    )
}

#[async_trait]
impl< T: SimNetwork> LightningNode for SimNode<'_, T> {
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
        let preimage_bytes = Sha256::hash(&preimage.0[..]).to_byte_array();
        let payment_hash = PaymentHash(preimage_bytes);

        self.in_flight.insert(payment_hash, receiver);

        let route = match find_payment_route(
            self.info.pubkey,
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
            }
        };

        // If we did successfully obtain a route, dispatch the payment through the network and then report success.
        self.network
            .lock()
            .await
            .dispatch_payment(self.info.pubkey, route, preimage, sender);

        Ok(payment_hash)
    }

    /// track_payment blocks until a payment outcome is returned for the payment hash provided, or the shutdown listener
    /// provided is triggered. This call will fail if the hash provided was not obtained by calling send_payment first.
    async fn track_payment(
        &mut self,
        hash: PaymentHash,
        listener: Listener,
    ) -> Result<PaymentResult, LightningError> {
        match self.in_flight.get_mut(&hash) {
            Some(receiver) => {
                select! {
                    biased;
                    _ = listener => Err(LightningError::TrackPaymentError("shutdown during payment tracking".to_string())),

                    // If we get a payment result back, remove from our in flight set of payments and return the result.
                    res = receiver => {
                        self.in_flight.remove(&hash);
                        res.map_err(|e| LightningError::TrackPaymentError(format!("channel receive err: {}", e)))?
                    },
                }
            }
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

/// WrappedLog implements LDK's logging trait so that we can provide pathfinding with a logger that uses our existing
/// logger. It downgrades info logs to debug logs because they contain specifics of pathfinding that we don't want on
/// our very minimal info level.
pub struct WrappedLog {}

impl Logger for WrappedLog {
    fn log(&self, record: &Record) {
        match record.level {
            Level::Gossip => log::trace!("{}", record.args),
            Level::Trace => log::trace!("{}", record.args),
            Level::Debug => log::debug!("{}", record.args),
            Level::Info => log::debug!("{}", record.args),
            Level::Warn => log::warn!("{}", record.args),
            Level::Error => log::error!("{}", record.args),
        }
    }
}

/// A workaround to convert the bitcoin::PublicKey version we're using to the bitcoin::PublicKey type that LDK is using.
fn ldk_pubkey(pk: PublicKey) -> bitcoin_ldk::secp256k1::PublicKey {
    bitcoin_ldk::secp256k1::PublicKey::from_str(&pk.to_string()).unwrap()
}
