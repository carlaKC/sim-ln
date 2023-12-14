use crate::{LightningError, LightningNode, NodeInfo, PaymentResult};
use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::PublicKey, Network};
use bitcoin_ldk::blockdata::constants::genesis_block;
use bitcoin_ldk::BlockHash;
use lightning::ln::features::ChannelFeatures;
use lightning::ln::{msgs::UnsignedChannelAnnouncement, PaymentHash, PaymentPreimage};
use lightning::routing::gossip::{ChannelInfo, ChannelUpdateInfo, NetworkGraph, NodeId};
use lightning::routing::router::Path;
use lightning::routing::utxo::{UtxoLookup, UtxoResult};
use lightning::util::logger::{Logger, Record};
use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use triggered::Listener;

pub struct Graph<L: Deref + std::marker::Send>
where
    L::Target: Logger,
{
    // nodes maps the public key of a node to a vector of its currently open channels (scid), used for graph lookups.
    nodes: Arc<Mutex<HashMap<PublicKey, GraphEntry>>>,

    // channels maps the scid of a channel to its current state.
    channels: Arc<Mutex<HashMap<u64, SimChannel>>>,

    // track all tasks spawned to process payments in the graph.
    tasks: JoinSet<()>,

    // a network graph used for pathfinding.
    graph: NetworkGraph<L>,
}

impl<L: Deref + std::marker::Send> Graph<L>
where
    <L as Deref>::Target: Logger,
{
    fn new(graph: NetworkGraph<L>) -> Result<Self, ()> {
        let mut nodes = HashMap::new();
        let mut channels = HashMap::new();

        for (short_chan_id, channel) in graph.read_only().channels().unordered_iter() {
            channels.insert(*short_chan_id, SimChannel::from_ldk(channel)?);
        }

        Ok(Graph {
            nodes: Arc::new(Mutex::new(nodes)),
            channels: Arc::new(Mutex::new(channels)),
            tasks: JoinSet::new(),
            graph,
        })
    }
}
struct WrappedLog {}

impl Logger for WrappedLog {
    // TODO: better log, ideally just imported. Must have levels + formatted args.
    fn log(&self, record: &Record) {
        log::info!("{}", record.line)
    }
}

// A mock utxo validator that we never use, we just need it for typing a none value.
struct UtxoValidator {}

impl UtxoLookup for UtxoValidator {
    fn get_utxo(&self, _genesis_hash: &BlockHash, _short_channel_id: u64) -> UtxoResult {
        unreachable!()
    }
}

fn setup_graph(nodes: Vec<NodeInfo>) -> Result<(), ()> {
    let graph = NetworkGraph::new(
        // same issue of two different dependencies.
        bitcoin_ldk::Network::Regtest,
        &WrappedLog {},
    );

    // Add all the channels provided to our graph. This will also add the nodes to our network graph because ldk adds
    // any missing nodes to its view.
    for node in nodes {
        let placeholder =
            bitcoin_ldk::secp256k1::PublicKey::from_str(&node.pubkey.to_string()).unwrap();

        let channel = UnsignedChannelAnnouncement {
            features: ChannelFeatures::empty(),
            chain_hash: genesis_block(bitcoin_ldk::Network::Regtest)
                .header
                .block_hash(),
            short_channel_id: 0,
            node_id_1: NodeId::from_pubkey(&placeholder),
            node_id_2: NodeId::from_pubkey(&placeholder),
            bitcoin_key_1: NodeId::from_pubkey(&placeholder),
            bitcoin_key_2: NodeId::from_pubkey(&placeholder),
            excess_data: Vec::new(),
        };

        if graph
            .update_channel_from_unsigned_announcement::<&UtxoValidator>(&channel, &None)
            .is_err()
        {
            return Err(());
        }
    }

    Ok(())
}

#[derive(Clone)]
struct GraphEntry {
    node_info: NodeInfo,
    node_capacities: Vec<u64>,
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

    async fn lookup_node(&self, node: &PublicKey) -> Result<GraphEntry, LightningError>;
}

#[async_trait]
impl<L: Deref + std::marker::Send + std::marker::Sync> SimNetwork for Graph<L>
where
    <L as Deref>::Target: Logger,
{
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

        self.tasks.spawn(propagate_payment(
            self.channels.clone(),
            source,
            dest,
            amount_msat,
            preimage,
            sender,
        ));

        receiver
    }

    /// lookup_node fetches a node's information from the graph.
    async fn lookup_node(&self, node: &PublicKey) -> Result<GraphEntry, LightningError> {
        match self.nodes.lock().await.get(node) {
            Some(g) => Ok(g.clone()),
            None => Err(LightningError::GetNodeInfoError(
                "Node not found".to_string(),
            )),
        }
    }
}

async fn propagate_payment(
    nodes: Arc<Mutex<HashMap<u64, SimChannel>>>,
    source: PublicKey,
    dest: PublicKey,
    amount_msat: u64,
    preimage: PaymentPreimage,
    sender: Sender<Result<PaymentResult, LightningError>>,
) {
    // TODO: pathfinding for actual route in the network.
    let route = Path {
        hops: vec![],
        blinded_tail: None,
    };

    // Get values for the first HTLC we'll send from the source node.
    let mut outgoing_node = source;
    let mut outgoing_amount = route.fee_msat() + route.final_value_msat();
    let mut outgoing_cltv = route
        .hops
        .iter()
        .fold(0, |sum, value| sum + value.cltv_expiry_delta);

    let preimage_bytes = Sha256::hash(&preimage.0[..]).to_byte_array();
    let payment_hash = PaymentHash(preimage_bytes);

    let mut fail_idx = None;
    let mut require_resolution = false;

    // Lookup each hop in the route and add the HTLC to its mock channel.
    for (i, hop) in route.hops.iter().enumerate() {
        let pubkey_str = format!("{}", hop.pubkey);
        let hop_pubkey = PublicKey::from_str(&pubkey_str).unwrap();

        match nodes.lock().await.get_mut(&hop.short_channel_id) {
            Some(channel) => {
                if channel
                    .add_htlc(
                        outgoing_node,
                        Htlc {
                            amount_msat: outgoing_amount,
                            cltv_expiry: outgoing_cltv,
                            hash: payment_hash,
                        },
                    )
                    .is_err()
                {
                    // Note: do this in a better way?
                    if i != 0 {
                        fail_idx = Some(i - 1);
                        require_resolution = true;
                    }

                    break;
                }

                // Once we've added the HTLC on this hop's channel, we want to check whether it has sufficient fee
                // and CLTV delta per the _next_ channel's policy (because fees and CLTV delta in LN are charged on
                // the outgoing link). We check the policy belonging to the node that we just forwarded to, which
                // represents the fee in that direction. Note that we don't check the final hop's requirements for CLTV
                // delta, that's out of scope at present.
                if i != route.hops.len() - 1 {
                    if let Some(channel) =
                        nodes.lock().await.get(&route.hops[i + 1].short_channel_id)
                    {
                        if channel
                            .check_htlc_forward(
                                hop_pubkey,
                                hop.cltv_expiry_delta,
                                outgoing_amount - hop.fee_msat, // TODO: check the amount that we calc fee on
                                hop.fee_msat,
                            )
                            .is_err()
                        {
                            // If we haven't met forwarding conditions for the next channel's policy, then we fail at
                            // index i, because we've already added the HTLC as outgoing.
                            fail_idx = Some(i)
                        }
                    }
                }
            }
            None => {
                if i != 0 {
                    fail_idx = Some(i - 1);
                    require_resolution = true;
                }

                let err = Err(LightningError::SendPaymentError(format!(
                    "channel {} not found for payment {} to {}",
                    hop.short_channel_id, amount_msat, dest
                )));

                if sender.send(err).is_err() {
                    // log a warning?
                }

                break;
            }
        }

        // Once we've taken the "hop" to the destination pubkey, it becomes the source of the next outgoing htlc.
        outgoing_node = hop_pubkey;
        outgoing_amount -= hop.fee_msat;
        outgoing_cltv -= hop.cltv_expiry_delta;

        // TODO: latency?
    }

    // If we failed adding our very first hop then we don't need to unwrap any htlcs.
    if !require_resolution {
        return;
    }

    // Once we've added our HTLC along the route (either all the way, successfully, or part of the way, with a failure
    // occurring along the way) we need to settle back the HTLC. We know the start point for this process and whether
    // the HTLC succeeded based on whether our fail_idx was populated.
    let resolution_idx = fail_idx.unwrap_or(route.hops.len() - 1);
    let success = fail_idx.is_none();

    for i in resolution_idx..0 {
        let hop = &route.hops[i];

        let incoming_node = if i == 0 {
            source
        } else {
            // Note: this is a _hideous_ workaround for the fact that we're using a different
            // version of bitcoin dep than LDK.
            let pubkey_str = format!("{}", route.hops[i - 1].pubkey);
            PublicKey::from_str(&pubkey_str).unwrap()
        };

        match nodes.lock().await.get_mut(&hop.short_channel_id) {
            Some(channel) => {
                if channel
                    .remove_htlc(incoming_node, payment_hash, success)
                    .is_err()
                {
                    panic!(
                        "could not remove htlc {} from {}",
                        hex::encode(payment_hash.0),
                        hop.short_channel_id
                    )
                }
            }
            None => {
                panic!(
                    "successfully added HTLC not found on resolution: {}",
                    hop.short_channel_id
                )
            }
        }
    }
}

#[derive(Copy, Clone)]
struct Htlc {
    hash: PaymentHash,
    amount_msat: u64,
    cltv_expiry: u32,
}

struct SimChannel {
    node_1: ChannelParticipant,
    node_2: ChannelParticipant,

    // Total capacity of the channel expressed in msat.
    capacity_msat: u64,
}

impl SimChannel {
    fn from_ldk(info: &ChannelInfo) -> Result<Self, ()> {
        let capacity_msat = info.capacity_sats.ok_or(())? * 1000;

        Ok(SimChannel {
            node_1: ChannelParticipant::from_ldk(
                info.node_one,
                info.one_to_two.clone().ok_or(())?,
                capacity_msat,
                true,
            )?,
            node_2: ChannelParticipant::from_ldk(
                info.node_two,
                info.two_to_one.clone().ok_or(())?,
                capacity_msat,
                false,
            )?,
            capacity_msat,
        })
    }
}

struct ChannelParticipant {
    id: PublicKey,
    max_htlc: u64,
    max_in_flight: u64,
    local_balance: u64,
    in_flight: HashMap<PaymentHash, Htlc>,
    cltv_expiry_delta: u32,
    base_fee: u64,
    fee_rate_prop: u64,
}

impl ChannelParticipant {
    fn from_ldk(
        node: NodeId,
        update: ChannelUpdateInfo,
        capacity_msat: u64,
        initiator: bool,
    ) -> Result<Self, ()> {
		// TODO: fix workaround with two different pubkey types
        let pk = PublicKey::from_slice(node.as_slice()).map_err(|_| ())?;

        Ok(ChannelParticipant {
            id: pk,
            max_htlc: 483, // TODO: infer from implementation?
            max_in_flight: update.htlc_maximum_msat,
            local_balance: if initiator { capacity_msat } else { 0 },
            in_flight: HashMap::new(),
            cltv_expiry_delta: update.cltv_expiry_delta as u32,
            base_fee: update.fees.base_msat as u64,
            fee_rate_prop: update.fees.proportional_millionths as u64,
        })
    }

    fn in_flight_total(&self) -> u64 {
        self.in_flight
            .iter()
            .fold(0, |sum, val| sum + val.1.amount_msat)
    }

    fn check_forward(&self, cltv_delta: u32, amt: u64, fee: u64) -> Result<(), ()> {
        if cltv_delta < self.cltv_expiry_delta {
            return Err(());
        }

        let expected_fee =
            self.base_fee as f64 + ((self.fee_rate_prop as f64 * amt as f64) / 1000000.0);
        if (fee as f64) < expected_fee {
            return Err(());
        }

        Ok(())
    }

    fn check_policy(&self, htlc: &Htlc) -> Result<(), ()> {
        if htlc.amount_msat > self.local_balance {
            return Err(());
        }

        if self.in_flight.len() as u64 + 1 > self.max_htlc {
            return Err(());
        }

        if self.in_flight_total() + htlc.amount_msat > self.max_in_flight {
            return Err(());
        }

        if htlc.cltv_expiry > 500000000 {
            return Err(());
        }

        Ok(())
    }

    fn add_outgoing_htlc(&mut self, htlc: Htlc) -> Result<(), ()> {
        self.check_policy(&htlc)?;

        match self.in_flight.get(&htlc.hash) {
            Some(_) => Err(()),
            None => {
                self.local_balance -= htlc.amount_msat;
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
                    self.local_balance += v.amount_msat
                }

                Ok(v)
            }
            None => Err(()),
        }
    }
}

impl SimChannel {
    fn add_htlc(&mut self, node: PublicKey, htlc: Htlc) -> Result<(), ()> {
        if htlc.amount_msat == 0 {
            return Err(());
        }

        if node == self.node_1.id {
            let res = self.node_1.add_outgoing_htlc(htlc);
            self.sanity_check();
            return res;
        }

        if node == self.node_2.id {
            let res = self.node_2.add_outgoing_htlc(htlc);
            self.sanity_check();
            return res;
        }

        Err(())
    }

    /// performs a sanity check on the total balances in a channel. Note that we do not currently include on-chain
    /// fees or reserve so these values should exactly match.
    fn sanity_check(&self) {
        let node_1_total = self.node_1.local_balance + self.node_1.in_flight_total();
        let node_2_total = self.node_2.local_balance + self.node_2.in_flight_total();

        if node_1_total + node_2_total != self.capacity_msat {
            panic!(
                "channel sanity check failed: total balance: {} != node_1: {} + node 2: {}",
                self.capacity_msat, node_1_total, node_2_total
            )
        }
    }

    fn remove_htlc(
        &mut self,
        incoming_node: PublicKey,
        hash: PaymentHash,
        success: bool,
    ) -> Result<(), ()> {
        // TODO: macro for this?
        if incoming_node == self.node_1.id {
            if let Ok(htlc) = self.node_1.remove_outgoing_htlc(hash, success) {
                // If the HTLC was settled, its amount is transferred to the remote party's local balance.
                // If it was failed, the above removal has already dealt with balance management.
                if success {
                    self.node_2.local_balance += htlc.amount_msat
                }
                self.sanity_check();

                return Ok(());
            } else {
                return Err(());
            }
        }

        if incoming_node == self.node_2.id {
            if let Ok(htlc) = self.node_2.remove_outgoing_htlc(hash, success) {
                // If the HTLC was settled, its amount is transferred to the remote party's local balance.
                // If it was failed, the above removal has already dealt with balance management.
                if success {
                    self.node_1.local_balance += htlc.amount_msat
                }

                self.sanity_check();
                return Ok(());
            } else {
                return Err(());
            }
        }

        Err(())
    }

    fn check_htlc_forward(
        &self,
        node: PublicKey,
        cltv_delta: u32,
        amount_msat: u64,
        fee_msat: u64,
    ) -> Result<(), ()> {
        if node == self.node_1.id {
            return self.node_1.check_forward(cltv_delta, amount_msat, fee_msat);
        }

        if node == self.node_2.id {
            return self.node_2.check_forward(cltv_delta, amount_msat, fee_msat);
        }

        Err(())
    }
}

struct SimNode<T: SimNetwork + Send + Sync> {
    info: NodeInfo,
    network: T,
    in_flight: HashMap<PaymentHash, Receiver<Result<PaymentResult, LightningError>>>,
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
        let payment_receiver =
            self.network
                .dispatch_payment(self.info.pubkey, dest, amount_msat, preimage);

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
        Ok(self.network.lookup_node(node_id).await?.node_info)
    }

    async fn list_channels(&mut self) -> Result<Vec<u64>, LightningError> {
        Ok(self
            .network
            .lookup_node(&self.info.pubkey)
            .await?
            .node_capacities)
    }
}
