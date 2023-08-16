use std::str::FromStr;

use crate::{LightningError, LightningNode, NodeInfo, PaymentOutcome};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::PaymentHash;
use log::info;
use tonic_lnd::{
    lnrpc::{GetInfoRequest, GetInfoResponse},
    routerrpc::TrackPaymentRequest,
    Client,
};

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
        _dest: PublicKey,
        _amount_msat: u64,
    ) -> Result<PaymentHash, LightningError> {
        unimplemented!()
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
