use std::{collections::HashMap, str::FromStr};

use crate::{
    utils::string_to_payment_hash, LightningError, LightningNode, NodeInfo, PaymentOutcome,
};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::{PaymentHash, PaymentPreimage};
use log::info;
use tonic_lnd::{
    lnrpc::{GetInfoRequest, GetInfoResponse},
    routerrpc::{SendPaymentRequest, TrackPaymentRequest},
    Client,
};

const KEYSEND_KEY: u64 = 5482373484;

#[allow(dead_code)]
pub struct LndNode {
    client: Client,
}

impl LndNode {
    pub async fn new(
        address: String,
        macaroon: String,
        cert: String,
    ) -> Result<Self, LightningError> {
        let client = tonic_lnd::connect(address, cert, macaroon)
            .await
            .map_err(|err| LightningError::ConnectionError(err.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl LightningNode for LndNode {
    async fn get_info(&self) -> Result<NodeInfo, LightningError> {
        let mut client = self.client.clone();
        let ln_client = client.lightning();

        let GetInfoResponse {
            identity_pubkey,
            features,
            alias,
            ..
        } = ln_client
            .get_info(GetInfoRequest {})
            .await
            .map_err(|err| LightningError::GetInfoError(err.to_string()))?
            .into_inner();

        Ok(NodeInfo {
            pubkey: PublicKey::from_str(&identity_pubkey)
                .map_err(|err| LightningError::GetInfoError(err.to_string()))?,
            features: features.keys().copied().collect(),
            alias,
        })
    }

    async fn send_payment(
        &self,
        dest: PublicKey,
        amount_msat: u64,
    ) -> Result<PaymentHash, LightningError> {
        let mut client = self.client.clone();
        let router_client = client.router();

        let amt_msat: i64 = amount_msat
            .try_into()
            .map_err(|_| LightningError::SendPaymentError("Invalid send amount".to_string()))?;

        let preimage = PaymentPreimage(rand::random());

        let mut dest_custom_records = HashMap::new();
        dest_custom_records.insert(KEYSEND_KEY, preimage.0.to_vec());

        let response = router_client
            .send_payment_v2(SendPaymentRequest {
                amt_msat,
                dest: dest.serialize().to_vec(),
                dest_custom_records,
                ..Default::default()
            })
            .await?;

        let mut stream = response.into_inner();

        let payment_hash = match stream.message().await? {
            Some(payment) => string_to_payment_hash(&payment.payment_hash)?,
            None => return Err(LightningError::SendPaymentError("No payment".to_string())),
        };

        Ok(payment_hash)
    }

    async fn track_payment(&self, hash: PaymentHash) -> Result<PaymentOutcome, LightningError> {
        let mut client = self.client.clone();
        let router_client = client.router();

        let response = router_client
            .track_payment_v2(TrackPaymentRequest {
                payment_hash: hash.0.to_vec(),
                no_inflight_updates: false,
            })
            .await?;

        let mut stream = response.into_inner();

        while let Some(payment) = stream.message().await? {
            info!("Payment: {payment:?}");
            if payment.status == 2 {
                return Ok(PaymentOutcome::Success);
            } else if payment.status == 3 {
                return Ok(PaymentOutcome::Failure);
            }
        }
        Ok(PaymentOutcome::Unknown)
    }
}