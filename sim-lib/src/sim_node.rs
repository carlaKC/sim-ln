use crate::{LightningError, LightningNode, NodeInfo, PaymentResult};
use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::PublicKey, Network};
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::router::Path;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use triggered::Listener;

pub struct Graph {
    // nodes maps the public key of a node to a vector of its currently open channels (scid), used for graph lookups.
    nodes: Arc<Mutex<HashMap<PublicKey, GraphEntry>>>,

    // channels maps the scid of a channel to its current state.
    channels: Arc<Mutex<HashMap<u64, SimChannel>>>,

    // track all tasks spawned to process payments in the graph.
    tasks: JoinSet<()>,
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
impl SimNetwork for Graph {
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
        let pubkey_str = format!("{}", hop.pubkey);
        outgoing_node = PublicKey::from_str(&pubkey_str).unwrap();
        outgoing_amount -= hop.fee_msat;
        outgoing_cltv -= hop.cltv_expiry_delta;

        // TODO: latency?
        // TODO: fee check?
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

struct ChannelParticipant {
    id: PublicKey,
    max_htlc: u64,
    max_in_flight: u64,
    local_balance: u64,
    in_flight: HashMap<PaymentHash, Htlc>,
}

impl ChannelParticipant {
    fn in_flight_total(&self) -> u64 {
        self.in_flight
            .iter()
            .fold(0, |sum, val| sum + val.1.amount_msat)
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
