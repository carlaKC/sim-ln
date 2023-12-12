use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::{secp256k1::PublicKey, Network};
use lightning::ln::{PaymentHash, PaymentPreimage};
use tokio::select;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use triggered::Listener;

use crate::{LightningError, LightningNode, NodeInfo, PaymentResult};

pub struct Graph {
    nodes: Arc<Mutex<HashMap<PublicKey, GraphEntry>>>,
    tasks: JoinSet<()>,
}

struct GraphEntry {
    node_info: NodeInfo,
    node_channels: HashMap<u64, SimChannel>,
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
            self.nodes.clone(),
            dest,
            amount_msat,
            preimage,
            sender,
        ));

        receiver
    }

    async fn lookup_node(&self, node: &PublicKey) -> Result<GraphEntry, LightningError> {
        match self.nodes.lock().await.get(node) {
            Some(g) => Ok(*g),
            None => Err(LightningError::GetNodeInfoError(
                "Node not found".to_string(),
            )),
        }
    }
}

async fn propagate_payment(
    nodes: Arc<Mutex<HashMap<PublicKey, GraphEntry>>>,
    dest: PublicKey,
    amount_msat: u64,
    _preimage: PaymentPreimage,
    sender: Sender<Result<PaymentResult, LightningError>>,
) {
    // TODO: pathfinding for actual route in the network.
    let route: Vec<Hop> = Vec::new();

    // Lookup each hop in the route and add the HTLC to its mock channel.
    for hop in route {
        match nodes.lock().await.get_mut(&hop.node_id) {
            Some(entry) => match entry.node_channels.get_mut(&hop.channel_id) {
                Some(channel) => channel.add_htlc(hop.amount_msat),
                None => {
                    let err = Err(LightningError::SendPaymentError(format!(
                        "channel {} not found for payment {} to {}",
                        hop.channel_id, amount_msat, dest
                    )));

                    match sender.send(err) {
                        Ok(_) => return,
                        Err(_) => return,
                    }

                    // TODO: unroll HTLCs added so far
                }
            },
            None => {
                let err = Err(LightningError::SendPaymentError(format!(
                    "node {} not found for payment of {} to {}",
                    hop.node_id, amount_msat, dest
                )));

                match sender.send(err) {
                    Ok(_) => return,
                    Err(_) => return,
                }

                // TODO: unroll HTLCs added so far
            }
        }

        // TODO: latency?
    }
}

struct SimChannel {
    capacity: u64,
}

impl SimChannel {
    fn add_htlc(&mut self, _amount_msat: u64) {
        unimplemented!()
    }
}

pub struct SimNode<T: SimNetwork + Send + Sync> {
    info: NodeInfo,
    network: T,
    in_flight: HashMap<PaymentHash, Receiver<Result<PaymentResult, LightningError>>>,
}

struct Hop {
    node_id: PublicKey,
    channel_id: u64,
    amount_msat: u64,
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
                    res = receiver => res.map_err(|e| LightningError::TrackPaymentError(format!("channel receive err: {}", e)))?,
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
            .node_channels
            .iter()
            .map(|(_, channel)| channel.capacity)
            .collect())
    }
}
