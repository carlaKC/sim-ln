use crate::{LightningError, LightningNode, NodeInfo, PaymentResult};
use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::PublicKey, Network};
use lightning::ln::{PaymentHash, PaymentPreimage};
use std::collections::HashMap;
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
        dest: PublicKey,
        amount_msat: u64,
        preimage: PaymentPreimage,
    ) -> Receiver<Result<PaymentResult, LightningError>> {
        let (sender, receiver) = channel();

        self.tasks.spawn(propagate_payment(
            self.channels.clone(),
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
    dest: PublicKey,
    amount_msat: u64,
    preimage: PaymentPreimage,
    sender: Sender<Result<PaymentResult, LightningError>>,
) {
    // TODO: pathfinding for actual route in the network.
    let route: Vec<Hop> = Vec::new();

    let preimage_bytes = Sha256::hash(&preimage.0[..]).to_byte_array();
    let payment_hash = PaymentHash(preimage_bytes);

    // Lookup each hop in the route and add the HTLC to its mock channel.
    for hop in route {
        match nodes.lock().await.get_mut(&hop.channel_id) {
            Some(channel) => {
                if channel
                    .add_htlc(
                        hop.node_out,
                        HTLC {
                            amount_msat: hop.amount_msat,
                            cltv_expiry: hop.cltv_expiry,
                            hash: payment_hash,
                        },
                    )
                    .is_err()
                {
                    // TODO: unroll HTLC?
                    return;
                }
            }
            None => {
                let err = Err(LightningError::SendPaymentError(format!(
                    "channel {} not found for payment {} to {}",
                    hop.channel_id, amount_msat, dest
                )));

                match sender.send(err) {
                    Ok(_) => return,
                    Err(_) => return,
                }

                // TODO: unroll HTLCs added so far if we error out
            }
        }

        // TODO: latency?
    }
}

#[derive(Copy, Clone)]
struct HTLC {
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
    in_flight: HashMap<PaymentHash, HTLC>,
}

impl ChannelParticipant {
    fn check_policy(
        &self,
        htlc: &HTLC,
        balance: u64,
        htlcs: &HashMap<PaymentHash, HTLC>,
    ) -> Result<(), ()> {
        if htlc.amount_msat > balance {
            return Err(());
        }

        if htlcs.len() as u64 + 1 > self.max_htlc {
            return Err(());
        }

        let in_flight_total = htlcs.iter().fold(0, |sum, val| sum + val.1.amount_msat);
        if in_flight_total + htlc.amount_msat > self.max_in_flight {
            return Err(());
        }

        if htlc.cltv_expiry > 500000000 {
            return Err(());
        }

        Ok(())
    }

    fn add_outgoing_htlc(&mut self, htlc: HTLC) -> Result<(), ()> {
        self.check_policy(&htlc, self.local_balance, &self.in_flight)?;

        match self.in_flight.get(&htlc.hash) {
            Some(_) => return Err(()),
            None => {
                self.local_balance -= htlc.amount_msat;
                self.in_flight.insert(htlc.hash, htlc);
                Ok(())
            }
        }
    }
}

impl SimChannel {
    fn add_htlc(&mut self, node: PublicKey, htlc: HTLC) -> Result<(), ()> {
        if htlc.amount_msat == 0 {
            return Err(());
        }

        if node == self.node_1.id {
            return self.node_1.add_outgoing_htlc(htlc);
        }

        if node == self.node_2.id {
            return self.node_2.add_outgoing_htlc(htlc);
        }

        // TODO: add sanity check that values add up.
        Err(())
    }
}

struct SimNode<T: SimNetwork + Send + Sync> {
    info: NodeInfo,
    network: T,
    in_flight: HashMap<PaymentHash, Receiver<Result<PaymentResult, LightningError>>>,
}

struct Hop {
    // TODO: figure out how LDK frames this?
    node_out: PublicKey,
    channel_id: u64,
    amount_msat: u64,
    cltv_expiry: u32,
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
        let payment_receiver = self.network.dispatch_payment(dest, amount_msat, preimage);

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
