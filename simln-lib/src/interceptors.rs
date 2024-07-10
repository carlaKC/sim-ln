use crate::sim_node::{CustomRecords, InterceptRequest, Interceptor};
use crate::SimulationError;
use async_trait::async_trait;
use rand_distr::{Distribution, Poisson};
use std::time::Duration;
use tokio::{select, time};

/// LatencyIntercepor is a HTLC interceptor that will delay HTLC forwarding by some randomly chosen delay.
pub struct LatencyIntercepor<D>
where
    D: Distribution<f32> + Send + Sync,
{
    latency_dist: D,
}

impl LatencyIntercepor<Poisson<f32>> {
    pub fn new_poisson(lambda_ms: f32) -> Result<Self, SimulationError> {
        let poisson_dist = Poisson::new(lambda_ms).map_err(|e| {
            SimulationError::SimulatedNetworkError(format!("Could not create possion: {e}"))
        })?;

        Ok(Self {
            latency_dist: poisson_dist,
        })
    }
}

#[async_trait]
impl<D> Interceptor for LatencyIntercepor<D>
where
    D: Distribution<f32> + Send + Sync,
{
    /// Introduces a random sleep time on the HTLC.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        let latency = self.latency_dist.sample(&mut rand::thread_rng());

        select! {
            // If the response channel is closed, they no longer need a response from us - something is shutting down.
            _ = req.response.closed() => {
                log::debug!("Latency interceptor existing due to closed channel.");
            },
            _ = time::sleep(Duration::from_millis(latency as u64)) =>{
                if let Err(e) = req.response.send(Ok(Ok(CustomRecords::default()))).await{
                    log::error!("Latency interceptor failed to resume HTLC: {e}");
                }
            }
        }
    }

    fn name(&self) -> String {
        "Latency Interceptor".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::Duration;

    use super::{Interceptor, LatencyIntercepor};
    use crate::sim_node::{CustomRecords, ForwardingError, HtlcRef, InterceptRequest};
    use crate::test_utils::get_random_keypair;
    use crate::ShortChannelID;
    use ntest::assert_true;
    use rand::distributions::Distribution;
    use rand::Rng;
    use tokio::sync::mpsc::channel;
    use tokio::time::timeout;

    /// Always returns the same value, useful for testing.
    struct ConstantDistribution {
        value: f32,
    }

    impl Distribution<f32> for ConstantDistribution {
        fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> f32 {
            self.value
        }
    }

    fn test_request() -> (
        InterceptRequest,
        tokio::sync::mpsc::Receiver<
            Result<Result<CustomRecords, ForwardingError>, Box<dyn Error + Send + Sync + 'static>>,
        >,
    ) {
        let (sender, receiver) = channel(1);
        let (_, pk) = get_random_keypair();
        let request = InterceptRequest {
            response: sender,
            forwarding_node: pk,
            incoming_htlc: HtlcRef {
                channel_id: ShortChannelID::from(123),
                index: 1,
            },
            incoming_custom_records: CustomRecords::default(),
            outgoing_channel_id: None,
            incoming_amount_msat: 100,
            outgoing_amount_msat: 50,
            incoming_expiry_height: 120,
            outgoing_expiry_height: 100,
        };

        (request, receiver)
    }

    /// Tests that the interceptor exits immediately if the response channel has already been closed.
    #[tokio::test]
    async fn test_response_closed() {
        // Set fixed dist to a high value so that the test won't flake.
        let latency_dist = ConstantDistribution { value: 1000.0 };
        let interceptor = LatencyIntercepor { latency_dist };

        let (request, mut receiver) = test_request();
        receiver.close();
        assert_true!(timeout(Duration::from_secs(10), async {
            interceptor.intercept_htlc(request).await;
        })
        .await
        .is_ok());
    }

    /// Tests the happy case where we wait for our latency and then return a result.
    #[tokio::test]
    async fn test_latency_response() {
        let latency_dist = ConstantDistribution { value: 0.0 };
        let interceptor = LatencyIntercepor { latency_dist };

        let (request, mut receiver) = test_request();
        // We should return immediately because timeout is zero.
        assert_true!(timeout(Duration::from_secs(1), async {
            interceptor.intercept_htlc(request).await;
        })
        .await
        .is_ok());

        // We should immediately receive a result from the interceptor.
        assert_true!(timeout(Duration::from_secs(1), async {
            assert_true!(receiver.try_recv().unwrap().is_ok());
        })
        .await
        .is_ok());
    }
}
