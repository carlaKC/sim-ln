use crate::{LightningError, LightningNode, NodeInfo, PaymentOutcome, PaymentResult};
use async_trait::async_trait;
use bitcoin::hashes::{sha256::Hash as Sha256, Hash};
use bitcoin::{secp256k1::PublicKey, Network};
// LDK uses a different version of bitcoin library than us, so we alias the types it use to allow use of both versions.
use bitcoin_ldk::{
    blockdata::{constants::genesis_block, script::Script},
    BlockHash, TxOut,
};
use core::fmt;
use lightning::ln::chan_utils::make_funding_redeemscript;
use lightning::ln::features::{ChannelFeatures, NodeFeatures};
use lightning::ln::{
    msgs::{LightningError as LdkError, UnsignedChannelAnnouncement, UnsignedChannelUpdate},
    PaymentHash, PaymentPreimage,
};
use lightning::routing::gossip::{NetworkGraph, NodeId};
use lightning::routing::router::{find_route, Path, Payee, PaymentParameters, RouteParameters};
use lightning::routing::scoring::{
    ProbabilisticScorer, ProbabilisticScoringDecayParameters, ProbabilisticScoringFeeParameters,
};
use lightning::routing::utxo::{UtxoLookup, UtxoResult};
use lightning::util::logger::{Level, Logger, Record};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use triggered::Listener;

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
}

impl Display for ForwardingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardingError::ZeroAmountHtlc => write!(f, "zero amount htlc"),
            ForwardingError::ChannelNotFound(chan_id) => write!(f, "channel {chan_id} not found"),
			ForwardingError::NodeNotFound(node) => write!(f, "node: {node} not found"),
            ForwardingError::PaymentHashExists(hash) => write!(f, "payment hash {} already forwarded", hex::encode(hash.0)),
			ForwardingError::InsufficientBalance(htlc_amt, local_bal) => write!(f, "local balance: {local_bal} insufficient for htlc: {htlc_amt}"),
			ForwardingError::LessThanMinimum(htlc_amt,min_amt ) => write!(f, "channel minimum: {min_amt} > htlc: {htlc_amt}"),
			ForwardingError::MoreThanMaximum(htlc_amt,max_amt )=> write!(f,"channel maximum: {max_amt} < htlc: {htlc_amt}"),
			ForwardingError::ExceedsInFlightCount(in_flight, max_in_flight ) => write!(f, "maximum in flight count: {max_in_flight} reached with {in_flight} htlcs"),
			ForwardingError::ExceedsInFlightTotal(htlc_amt, in_flight_amt, max_in_flight) => write!(f, "maximum in flight amount: {max_in_flight} with {in_flight_amt} in flight exceeded by htlc: {htlc_amt}"),
			ForwardingError::ExpiryInSeconds(cltv_delta) => write!(f, "cltv: {cltv_delta} expressed in seconds"),
			ForwardingError::InsufficientCltvDelta(cltv_delta, min_delta ) => write!(f, "minimum cltv delta: {min_delta} not met by: {cltv_delta}"),
			ForwardingError::InsufficientFee(htlc_fee, base_fee, prop_fee, expected_fee) => write!(f,"expected fee: {expected_fee} (base: {base_fee}, prop: {prop_fee}), got: {htlc_fee}"),
        }
    }
}

/// Graph is the top level struct that is used to coordinate simulation of lightning nodes.
pub struct Graph<'a> {
    /// nodes caches the list of nodes in the network with a vector of their channel capacities, only used for quick
    /// lookup.
    nodes: HashMap<PublicKey, Vec<u64>>,

    /// channels maps the scid of a channel to its current simulation state.
    channels: Arc<Mutex<HashMap<u64, SimulatedChannel>>>,

    /// track all tasks spawned to process payments in the graph.
    tasks: JoinSet<()>,

    /// a read-only network graph used for pathfinding.
    graph: NetworkGraph<&'a WrappedLog>,
}

impl Graph<'_> {
    pub fn new(graph_channels: Vec<SimulatedChannel>) -> Result<Self, LdkError> {
        let mut nodes: HashMap<PublicKey, Vec<u64>> = HashMap::new();
        let mut channels = HashMap::new();

        for channel in graph_channels.iter() {
            channels.insert(channel.short_channel_id, channel.clone());

            macro_rules! insert_node_entry {
                ($pubkey:expr) => {{
                    match nodes.entry($pubkey) {
                        Entry::Occupied(o) => o.into_mut().push(channel.capacity_msat),
                        Entry::Vacant(v) => {
                            v.insert(vec![channel.capacity_msat]);
                        }
                    }
                }};
            }

            insert_node_entry!(channel.node_1.policy.pubkey);
            insert_node_entry!(channel.node_2.policy.pubkey);
        }

        let graph = populate_network_graph(graph_channels)?;

        Ok(Graph {
            nodes,
            channels: Arc::new(Mutex::new(channels)),
            tasks: JoinSet::new(),
            graph,
        })
    }
}

/// Produces a map of node public key to lightning node implementation to be used for simulations.
pub async fn ln_node_from_graph(
    graph: Arc<Mutex<Graph<'_>>>,
) -> HashMap<PublicKey, Arc<Mutex<dyn LightningNode + Send + '_>>> {
    let mut nodes: HashMap<PublicKey, Arc<Mutex<dyn LightningNode + Send>>> = HashMap::new();

    for pk in graph.lock().await.nodes.keys() {
        nodes.insert(*pk, Arc::new(Mutex::new(SimNode::new(*pk, graph.clone()))));
    }

    nodes
}

/// Populates a network graph based on the set of simulated channels provided. This function *only* applies channel
/// announcements, which has the effect of adding the nodes in each channel to the graph, because LDK does not export
/// all of the fields required to apply node announcements. This means that we will not have node-level information
/// (such as features) available in the routing graph.
fn populate_network_graph(
    channels: Vec<SimulatedChannel>,
) -> Result<NetworkGraph<&'static WrappedLog>, LdkError> {
    let graph = NetworkGraph::new(bitcoin_ldk::Network::Regtest, &WrappedLog {});

    let chain_hash = genesis_block(bitcoin_ldk::Network::Regtest)
        .header
        .block_hash();

    for channel in channels {
        let node_1_pk = ldk_pubkey(channel.node_1.policy.pubkey);
        let node_2_pk = ldk_pubkey(channel.node_2.policy.pubkey);

        let announcement = UnsignedChannelAnnouncement {
            // For our purposes we don't currently need any channel level features.
            features: ChannelFeatures::empty(),
            chain_hash,
            short_channel_id: channel.short_channel_id,
            node_id_1: NodeId::from_pubkey(&node_1_pk),
            node_id_2: NodeId::from_pubkey(&node_2_pk),
            // Note: we don't need bitcoin keys for our purposes, so we just copy them *but* remember that we do use
            // this for our fake utxo validation so they do matter for producing the script that we mock validate.
            bitcoin_key_1: NodeId::from_pubkey(&node_1_pk),
            bitcoin_key_2: NodeId::from_pubkey(&node_2_pk),
            // Internal field used by LDK, we don't need it.
            excess_data: Vec::new(),
        };

        let utxo_validator = UtxoValidator {
            amount_sat: channel.capacity_msat / 1000,
            script: make_funding_redeemscript(&node_1_pk, &node_2_pk).to_v0_p2wsh(),
        };

        graph.update_channel_from_unsigned_announcement(&announcement, &Some(&utxo_validator))?;

        macro_rules! generate_and_update_channel {
            ($node:expr, $flags:expr) => {{
                let update = UnsignedChannelUpdate {
                    chain_hash,
                    short_channel_id: channel.short_channel_id,
                    timestamp: 1702667117, // TODO: current time
                    flags: $flags,         // TODO: double check
                    cltv_expiry_delta: $node.policy.cltv_expiry_delta as u16,
                    htlc_minimum_msat: $node.policy.min_htlc_size_msat,
                    htlc_maximum_msat: $node.policy.max_htlc_size_msat,
                    fee_base_msat: $node.policy.base_fee as u32,
                    fee_proportional_millionths: $node.policy.fee_rate_prop as u32,
                    excess_data: Vec::new(),
                };

                graph.update_channel_unsigned(&update)?;
            }};
        }

        // The least significant bit of the channel flag field represents the direction that the channel update
        // applies to. This value is interpreted as node_1 if it is zero, and node_2 otherwise.
        generate_and_update_channel!(channel.node_1, 0);
        generate_and_update_channel!(channel.node_2, 1);
    }

    Ok(graph)
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

/// WrappedLog implements LDK's logging trait so that we can provide pathfinding with a logger that uses our existing
/// logger.
struct WrappedLog {}

impl Logger for WrappedLog {
    fn log(&self, record: &Record) {
        match record.level {
            Level::Gossip => log::trace!("{}", record.args),
            Level::Trace => log::trace!("{}", record.args),
            Level::Debug => log::debug!("{}", record.args),
            Level::Info => log::info!("{}", record.args),
            Level::Warn => log::warn!("{}", record.args),
            Level::Error => log::error!("{}", record.args),
        }
    }
}

/// UtxoValidator is a mock utxo validator that just returns a fake output with the desired capacity for a channel.
struct UtxoValidator {
    amount_sat: u64,
    script: Script,
}

impl UtxoLookup for UtxoValidator {
    fn get_utxo(&self, _genesis_hash: &BlockHash, _short_channel_id: u64) -> UtxoResult {
        UtxoResult::Sync(Ok(TxOut {
            value: self.amount_sat,
            script_pubkey: self.script.clone(),
        }))
    }
}

#[async_trait]
trait SimNetwork {
    fn dispatch_payment(
        &mut self,
        source: PublicKey,
        dest: PublicKey,
        amount_msat: u64,
        preimage: PaymentPreimage,
    ) -> Receiver<Result<PaymentResult, LightningError>>;

    async fn lookup_node(&self, node: &PublicKey) -> Result<(NodeInfo, Vec<u64>), LightningError>;
}

#[async_trait]
impl SimNetwork for Graph<'_> {
    /// dispatch_payment asynchronously propagates a payment through the simulated network, returning a tracking
    /// channel that can be used to obtain the result of the payment.
    fn dispatch_payment(
        &mut self,
        source: PublicKey,
        dest: PublicKey,
        amount_msat: u64,
        preimage: PaymentPreimage,
    ) -> Receiver<Result<PaymentResult, LightningError>> {
        let (sender, receiver) = channel();

        let params = ProbabilisticScoringDecayParameters::default();
        let scorer = ProbabilisticScorer::new(params, &self.graph, &WrappedLog {});

        log::info!("CKC: dispatch payment - finding route");
        let route = match find_route(
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
            &self.graph,
            None,
            &WrappedLog {},
            &scorer,
            &ProbabilisticScoringFeeParameters::default(),
            &[0; 32],
        ) {
            Ok(path) => path,
            Err(e) => {
                log::trace!("Could not find path for payment: {:?}.", e);

                if let Err(e) = sender.send(Ok(PaymentResult {
                    htlc_count: 0,
                    payment_outcome: PaymentOutcome::RouteNotFound,
                })) {
                    log::error!("Could not send payment result: {:?}.", e);
                }

                return receiver;
            }
        };

        log::info!("CKC: dispatch payment - found route");
        // Since we're not supporting MPP, just grab the first path off our route. If we don't have at least one path,
        // log a warning - this is unexpected - and fail the payment.
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

                return receiver;
            }
        };

        log::info!("CKC: dispatch payment - spinning up task");
        self.tasks.spawn(propagate_payment(
            self.channels.clone(),
            source,
            path.clone(),
            preimage,
            sender,
        ));

        receiver
    }

    /// lookup_node fetches a node's information and channel capacities.
    async fn lookup_node(&self, node: &PublicKey) -> Result<(NodeInfo, Vec<u64>), LightningError> {
        match self.nodes.get(node) {
            Some(channels) => Ok((node_info(*node), channels.clone())),
            None => Err(LightningError::GetNodeInfoError(
                "Node not found".to_string(),
            )),
        }
    }
}

/// Adds htlcs to the simulation state along the path provided. Returning the index in the path from which to fail
/// back htlcs (if any) and a forwading error if the payment is not successfully added to the entire path.
async fn add_htlcs(
    nodes: Arc<Mutex<HashMap<u64, SimulatedChannel>>>,
    source: PublicKey,
    route: Path,
    payment_hash: PaymentHash,
) -> Result<(), (Option<usize>, ForwardingError)> {
    let mut outgoing_node = source;
    let mut outgoing_amount = route.fee_msat() + route.final_value_msat();
    let mut outgoing_cltv = route
        .hops
        .iter()
        .fold(0, |sum, value| sum + value.cltv_expiry_delta);

    let mut fail_idx = None;

    log::info!("CKC: add_htlcs - adding htlcs");
    for (i, hop) in route.hops.iter().enumerate() {
        let pubkey_str = format!("{}", hop.pubkey);
        let hop_pubkey = PublicKey::from_str(&pubkey_str).unwrap();

        log::info!(
            "CKC: add_htlcs - adding to channel {}",
            hop.short_channel_id
        );

        let mut node_lock = nodes.lock().await;

        match node_lock.get_mut(&hop.short_channel_id) {
            Some(channel) => {
                if let Err(e) = channel.add_htlc(
                    outgoing_node,
                    Htlc {
                        amount_msat: outgoing_amount,
                        cltv_expiry: outgoing_cltv,
                        hash: payment_hash,
                    },
                ) {
                    // If we couldn't add to this HTLC, we only need to fail back from the preceeding hop, so we don't
                    // have to progress our fail_idx.
                    return Err((fail_idx, e));
                }

                // If the HTLC was successfully added, then we'll need to remove the HTLC from this channel if we fail,
                // so we progress our failure index to include this node.
                fail_idx = Some(i);

                // Once we've added the HTLC on this hop's channel, we want to check whether it has sufficient fee
                // and CLTV delta per the _next_ channel's policy (because fees and CLTV delta in LN are charged on
                // the outgoing link). We check the policy belonging to the node that we just forwarded to, which
                // represents the fee in that direction.
                //
                // Note that we don't check the final hop's requirements for CLTV delta at present.
                if i != route.hops.len() - 1 {
                    if let Some(channel) = node_lock.get(&route.hops[i + 1].short_channel_id) {
                        if let Err(e) = channel.check_htlc_forward(
                            hop_pubkey,
                            hop.cltv_expiry_delta,
                            outgoing_amount - hop.fee_msat,
                            hop.fee_msat,
                        ) {
                            // If we haven't met forwarding conditions for the next channel's policy, then we fail at
                            // the current index, because we've already added the HTLC as outgoing.
                            return Err((fail_idx, e));
                        }
                    }
                }
            }
            None => {
                return Err((
                    fail_idx,
                    ForwardingError::ChannelNotFound(hop.short_channel_id),
                ))
            }
        }

        // Once we've taken the "hop" to the destination pubkey, it becomes the source of the next outgoing htlc.
        outgoing_node = hop_pubkey;
        outgoing_amount -= hop.fee_msat;
        outgoing_cltv -= hop.cltv_expiry_delta;

        // TODO: introduce artificial latency between hops?
    }

    Ok(())
}

/// Removes htlcs from the simulation state from the index in the path provided (backwards).
async fn remove_htlcs(
    nodes: Arc<Mutex<HashMap<u64, SimulatedChannel>>>,
    resolution_idx: usize,
    source: PublicKey,
    route: Path,
    payment_hash: PaymentHash,
    success: bool,
) -> Result<(), LightningError> {
    log::info!("CKC removing htlcs");
    for i in resolution_idx..0 {
        let hop = &route.hops[i];

        // When we add HTLCs, we do so on the state of the node that sent the htlc along the channel so we need to
        // look up our incoming node so that we can remove it when we go backwards. For the first htlc, this is just
        // the sending node, otherwise it's the hop before.
        let incoming_node = if i == 0 {
            source
        } else {
            local_pubkey(route.hops[i - 1].pubkey)
        };

        match nodes.lock().await.get_mut(&hop.short_channel_id) {
            Some(channel) => {
                if channel
                    .remove_htlc(incoming_node, payment_hash, success)
                    .is_err()
                {
                    // TODO: signal critical error, we should always find our htlcs.
                    return Err(LightningError::SendPaymentError(format!(
                        "could not remove htlc {} from {}",
                        hex::encode(payment_hash.0),
                        hop.short_channel_id
                    )));
                }
            }
            None => {
                // TODO: signal critical error, we should always find channels we've already used.
                return Err(LightningError::SendPaymentError(format!(
                    "successfully added HTLC not found on resolution: {}",
                    hop.short_channel_id
                )));
            }
        }
    }

    Ok(())
}

/// Finds a payment path from the source to destination nodes provided, and propagates the appropriate htlcs through
/// the simulated network, notifying the sender channel provided of the payment outcome.
async fn propagate_payment(
    nodes: Arc<Mutex<HashMap<u64, SimulatedChannel>>>,
    source: PublicKey,
    route: Path,
    preimage: PaymentPreimage,
    sender: Sender<Result<PaymentResult, LightningError>>,
) {
    let preimage_bytes = Sha256::hash(&preimage.0[..]).to_byte_array();
    let payment_hash = PaymentHash(preimage_bytes);

    log::info!("CKC: propagate payment - adding htlcs");
    let notify_result = match add_htlcs(nodes.clone(), source, route.clone(), payment_hash).await {
        Ok(_) => {
            log::info!("CKC: propagate payment - removing htlcs (success)");
            if let Err(e) = remove_htlcs(
                nodes,
                route.hops.len() - 1,
                source,
                route,
                payment_hash,
                true,
            )
            .await
            {
                // TODO: critical error, our state machine isn't working.
                log::error!("Could not remove successful htlc: {e}.");
            }

            log::info!("CKC: propagate payment - removed htlcs (success)");
            PaymentResult {
                htlc_count: 1,
                payment_outcome: PaymentOutcome::Success,
            }
        }
        Err((fail_idx, err)) => {
            // If we partially added HTLCs along the route, we need to fail them back to the source to clean up our
            // partial state. It's possible that we failed with the very first add, and then we don't need to clean
            // anything up.
            if let Some(resolution_idx) = fail_idx {
                if let Err(e) =
                    remove_htlcs(nodes, resolution_idx, source, route, payment_hash, false).await
                {
                    // TODO: critical error, our state machine isn't working.
                    log::error!("Could not remove htlcs: {e}.");
                }
            }

            // We have more information about failures because we're in control of the whole route, so we log the
            // actual failure reason and then fail back with unknown failure type.
            log::debug!(
                "Forwarding failure for simulated payment {}: {err}",
                hex::encode(payment_hash.0)
            );
            PaymentResult {
                htlc_count: 0,
                payment_outcome: PaymentOutcome::Unknown,
            }
        }
    };

    log::info!("CKC: propagate payment - sending notification");
    if let Err(e) = sender.send(Ok(notify_result)) {
        log::error!("Could not notify payment result: {:?}.", e);
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

    fn remove_outgoing_htlc(&mut self, hash: PaymentHash, success: bool) -> Result<Htlc, ()> {
        match self.in_flight.remove(&hash) {
            Some(v) => {
                // If the HTLC failed, pending balance returns to local balance.
                if !success {
                    self.local_balance_msat += v.amount_msat
                }

                Ok(v)
            }
            None => Err(()),
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
            let res = self.node_1.add_outgoing_htlc(htlc);
            self.sanity_check();
            return res;
        }

        if node == self.node_2.policy.pubkey {
            let res = self.node_2.add_outgoing_htlc(htlc);
            self.sanity_check();
            return res;
        }

        Err(ForwardingError::NodeNotFound(node))
    }

    /// Performs a sanity check on the total balances in a channel. Note that we do not currently include on-chain
    /// fees or reserve so these values should exactly match.
    fn sanity_check(&self) {
        let node_1_total = self.node_1.local_balance_msat + self.node_1.in_flight_total();
        let node_2_total = self.node_2.local_balance_msat + self.node_2.in_flight_total();

        if node_1_total + node_2_total != self.capacity_msat {
            panic!(
                "channel sanity check failed: total balance: {} != node_1: {} + node 2: {}",
                self.capacity_msat, node_1_total, node_2_total
            )
        }
    }

    /// Removes a htlc from the appropriate size of the simulated channel, settling balances across channel sides
    /// based on the success of the htlc.
    fn remove_htlc(
        &mut self,
        incoming_node: PublicKey,
        hash: PaymentHash,
        success: bool,
    ) -> Result<(), ()> {
        // TODO: macro for this?
        if incoming_node == self.node_1.policy.pubkey {
            if let Ok(htlc) = self.node_1.remove_outgoing_htlc(hash, success) {
                // If the HTLC was settled, its amount is transferred to the remote party's local balance.
                // If it was failed, the above removal has already dealt with balance management.
                if success {
                    self.node_2.local_balance_msat += htlc.amount_msat
                }
                self.sanity_check();

                return Ok(());
            } else {
                return Err(());
            }
        }

        if incoming_node == self.node_2.policy.pubkey {
            if let Ok(htlc) = self.node_2.remove_outgoing_htlc(hash, success) {
                // If the HTLC was settled, its amount is transferred to the remote party's local balance.
                // If it was failed, the above removal has already dealt with balance management.
                if success {
                    self.node_1.local_balance_msat += htlc.amount_msat
                }

                self.sanity_check();
                return Ok(());
            } else {
                return Err(());
            }
        }

        Err(())
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

/// A wrapper struct used to implement the LightningNode trait (can be thought of as "the" lightning node). Passes
/// all functionality through to a coordinating simulation network.
struct SimNode<T: SimNetwork + Send + Sync> {
    info: NodeInfo,
    network: Arc<Mutex<T>>,
    in_flight: HashMap<PaymentHash, Receiver<Result<PaymentResult, LightningError>>>,
}

impl<T: SimNetwork + Send + Sync> SimNode<T> {
    pub fn new(pubkey: PublicKey, network: Arc<Mutex<T>>) -> Self {
        SimNode {
            info: node_info(pubkey),
            network,
            in_flight: HashMap::new(),
        }
    }
}

#[async_trait]
impl<T: SimNetwork + Send + Sync> LightningNode for SimNode<T> {
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
        let preimage = PaymentPreimage(rand::random());
        log::info!("CKC: send_payment - dispatching payment");
        let payment_receiver = self.network.lock().await.dispatch_payment(
            self.info.pubkey,
            dest,
            amount_msat,
            preimage,
        );

        log::info!("CKC: send_payment - dispatched payment");
        let preimage_bytes = Sha256::hash(&preimage.0[..]).to_byte_array();
        let payment_hash = PaymentHash(preimage_bytes);

        self.in_flight.insert(payment_hash, payment_receiver);

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

/// A workaround to convert the bitcoin::PublicKey version we're using to the bitcoin::PublicKey type that LDK is using.
fn ldk_pubkey(pk: PublicKey) -> bitcoin_ldk::secp256k1::PublicKey {
    bitcoin_ldk::secp256k1::PublicKey::from_str(&pk.to_string()).unwrap()
}

/// A workaround to convert the bitcoin::PublicKey version that LDK is using to the bitcoin::PublicKey type that we're
/// using.
fn local_pubkey(pk: bitcoin_ldk::secp256k1::PublicKey) -> PublicKey {
    PublicKey::from_str(&format!("{}", pk)).unwrap()
}
