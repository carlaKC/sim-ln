use bitcoin::secp256k1::PublicKey;
use sim_lib::sim_node::{ln_node_from_graph, ChannelPolicy, Graph, SimulatedChannel};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::anyhow;
use clap::builder::TypedValueParser;
use clap::Parser;
use log::LevelFilter;
use sim_lib::{
    cln::ClnNode, lnd::LndNode, ActivityDefinition, LightningError, LightningNode, NodeConnection,
    NodeId, SimParams, Simulation,
};
use simple_logger::SimpleLogger;

/// The default expected payment amount for the simulation, around ~$10 at the time of writing.
pub const EXPECTED_PAYMENT_AMOUNT: u64 = 3_800_000;

/// The number of times over each node in the network sends its total deployed capacity in a calendar month.
pub const ACTIVITY_MULTIPLIER: f64 = 2.0;

/// Default batch size to flush result data to disk
const DEFAULT_PRINT_BATCH_SIZE: u32 = 500;

/// Deserializes a f64 as long as it is positive and greater than 0.
fn deserialize_f64_greater_than_zero(x: String) -> Result<f64, String> {
    match x.parse::<f64>() {
        Ok(x) => {
            if x > 0.0 {
                Ok(x)
            } else {
                Err(format!(
                    "capacity_multiplier must be higher than 0. {x} received."
                ))
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the simulation file to be used by the simulator
    #[clap(index = 1)]
    sim_file: PathBuf,
    /// Total time the simulator will be running
    #[clap(long, short)]
    total_time: Option<u32>,
    /// Number of activity results to batch together before printing to csv file [min: 1]
    #[clap(long, short, default_value_t = DEFAULT_PRINT_BATCH_SIZE, value_parser = clap::builder::RangedU64ValueParser::<u32>::new().range(1..u32::MAX as u64))]
    print_batch_size: u32,
    /// Level of verbosity of the messages displayed by the simulator.
    /// Possible values: [off, error, warn, info, debug, trace]
    #[clap(long, short, verbatim_doc_comment, default_value = "info")]
    log_level: LevelFilter,
    /// Expected payment amount for the random activity generator
    #[clap(long, short, default_value_t = EXPECTED_PAYMENT_AMOUNT, value_parser = clap::builder::RangedU64ValueParser::<u64>::new().range(1..u64::MAX))]
    expected_pmt_amt: u64,
    /// Multiplier of the overall network capacity used by the random activity generator
    #[clap(long, short, default_value_t = ACTIVITY_MULTIPLIER, value_parser = clap::builder::StringValueParser::new().try_map(deserialize_f64_greater_than_zero))]
    capacity_multiplier: f64,
    /// Do not create an output file containing the simulations results
    #[clap(long, default_value_t = false)]
    no_results: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    SimpleLogger::new()
        .with_level(LevelFilter::Warn)
        .with_module_level("sim_lib", cli.log_level)
        .with_module_level("sim_cli", cli.log_level)
        .init()
        .unwrap();

    let SimParams { nodes, activity } =
        serde_json::from_str(&std::fs::read_to_string(cli.sim_file)?)
            .map_err(|e| anyhow!("Could not deserialize node connection data or activity description from simulation file (line {}, col {}).", e.line(), e.column()))?;

    let mut clients: HashMap<PublicKey, Arc<Mutex<dyn LightningNode + Send>>> = HashMap::new();
    let mut pk_node_map = HashMap::new();
    let mut alias_node_map = HashMap::new();

    for connection in nodes {
        // TODO: Feels like there should be a better way of doing this without having to Arc<Mutex<T>>> it at this time.
        // Box sort of works, but we won't know the size of the dyn LightningNode at compile time so the compiler will
        // scream at us when trying to create the Arc<Mutex>> later on while adding the node to the clients map
        let node: Arc<Mutex<dyn LightningNode + Send>> = match connection {
            NodeConnection::LND(c) => Arc::new(Mutex::new(LndNode::new(c).await?)),
            NodeConnection::CLN(c) => Arc::new(Mutex::new(ClnNode::new(c).await?)),
        };

        let node_info = node.lock().await.get_info().clone();

        log::info!(
            "Connected to {} - Node ID: {}.",
            node_info.alias,
            node_info.pubkey
        );

        if clients.contains_key(&node_info.pubkey) {
            anyhow::bail!(LightningError::ValidationError(format!(
                "duplicated node: {}.",
                node_info.pubkey
            )));
        }

        if alias_node_map.contains_key(&node_info.alias) {
            anyhow::bail!(LightningError::ValidationError(format!(
                "duplicated node: {}.",
                node_info.alias
            )));
        }

        clients.insert(node_info.pubkey, node);
        pk_node_map.insert(node_info.pubkey, node_info.clone());
        alias_node_map.insert(node_info.alias.clone(), node_info);
    }

    let mut validated_activities = vec![];
    // Make all the activities identifiable by PK internally
    for act in activity.into_iter() {
        // We can only map aliases to nodes we control, so if either the source or destination alias
        // is not in alias_node_map, we fail
        let source = if let Some(source) = match &act.source {
            NodeId::PublicKey(pk) => pk_node_map.get(pk),
            NodeId::Alias(a) => alias_node_map.get(a),
        } {
            source.clone()
        } else {
            anyhow::bail!(LightningError::ValidationError(format!(
                "activity source {} not found in nodes.",
                act.source
            )));
        };

        let destination = match &act.destination {
            NodeId::Alias(a) => {
                if let Some(info) = alias_node_map.get(a) {
                    info.clone()
                } else {
                    anyhow::bail!(LightningError::ValidationError(format!(
                        "unknown activity destination: {}.",
                        act.destination
                    )));
                }
            }
            NodeId::PublicKey(pk) => {
                if let Some(info) = pk_node_map.get(pk) {
                    info.clone()
                } else {
                    clients
                        .get(&source.pubkey)
                        .unwrap()
                        .lock()
                        .await
                        .get_node_info(pk)
                        .await
                        .map_err(|e| {
                            log::debug!("{}", e);
                            LightningError::ValidationError(format!(
                                "Destination node unknown or invalid: {}.",
                                pk,
                            ))
                        })?
                }
            }
        };

        validated_activities.push(ActivityDefinition {
            source,
            destination,
            interval_secs: act.interval_secs,
            amount_msat: act.amount_msat,
        });
    }

    let capacity = 300000000;
    let pubkey_1 =
        PublicKey::from_str("039ae6b91fbec1b400adffcd7f7132e81efbb5aaeeeb061903695a919652aee761")?;
    let alice_to_bob = ChannelPolicy {
        pubkey: pubkey_1,
        max_htlc_count: 483,
        max_in_flight_msat: capacity / 2,
        min_htlc_size_msat: 1,
        max_htlc_size_msat: capacity / 2,
        cltv_expiry_delta: 40,
        base_fee: 1000,
        fee_rate_prop: 3500,
    };

    let pubkey_2 =
        PublicKey::from_str("0275ade20b15f2a309d8db2d7ea4f5004129204b83d2307433292f183bdbe5df2e")?;
    let bob_to_alice = ChannelPolicy {
        pubkey: pubkey_2,
        max_htlc_count: 483,
        max_in_flight_msat: capacity / 2,
        min_htlc_size_msat: 1,
        max_htlc_size_msat: capacity / 2,
        cltv_expiry_delta: 40,
        base_fee: 2000,
        fee_rate_prop: 1,
    };

    let bob_to_carol = ChannelPolicy {
        pubkey: pubkey_2,
        max_htlc_count: 483,
        max_in_flight_msat: capacity / 2,
        min_htlc_size_msat: 1,
        max_htlc_size_msat: capacity / 2,
        cltv_expiry_delta: 40,
        base_fee: 1000,
        fee_rate_prop: 1000,
    };

    let pubkey_3 =
        PublicKey::from_str("028a4929f8c7fe3ce735f86d35e716efe406956dfe6ff1e1f88ea11207976a720b")?;
    let carol_to_bob = ChannelPolicy {
        pubkey: pubkey_3,
        max_htlc_count: 483,
        max_in_flight_msat: capacity / 2,
        min_htlc_size_msat: 1,
        max_htlc_size_msat: capacity / 2,
        cltv_expiry_delta: 15,
        base_fee: 2000,
        fee_rate_prop: 1,
    };

    let chan_alice_bob = SimulatedChannel::new(capacity, 123, alice_to_bob, bob_to_alice);

    let chan_bob_carol = SimulatedChannel::new(capacity, 456, bob_to_carol, carol_to_bob);

    // TODO: use the shutdown trigger and listener across simulator and graph.
    let (shutdown_trigger, shutdown_listener) = triggered::trigger();
    let graph = match Graph::new(
        vec![chan_alice_bob, chan_bob_carol],
        shutdown_trigger,
        shutdown_listener,
    ) {
        Ok(graph) => Arc::new(Mutex::new(graph)),
        Err(e) => anyhow::bail!("failed: {:?}", e),
    };

    let sim = Simulation::new(
        ln_node_from_graph(graph).await,
        validated_activities,
        cli.total_time,
        cli.print_batch_size,
        cli.expected_pmt_amt,
        cli.capacity_multiplier,
        cli.no_results,
    );
    let sim2 = sim.clone();

    ctrlc::set_handler(move || {
        log::info!("Shutting down simulation.");
        sim2.shutdown();
    })?;

    sim.run().await?;

    Ok(())
}
