//! Helpers for constructing a subxt `OnlineClient` backed by jsonrpsee with rustls.
//!
//! subxt 0.34's `native` feature unconditionally enables jsonrpsee's `native-tls` transport
//! when the `jsonrpsee` feature is also active, pulling in `openssl-sys` which breaks
//! cross-compilation. We avoid that by:
//! 1. Enabling subxt with only `native` (not `jsonrpsee`), so `dep:jsonrpsee` is not
//!    activated and the `jsonrpsee?/client-ws-transport-native-tls` conditional has no effect.
//! 2. Adding jsonrpsee directly with only the `client-ws-transport-webpki-tls` feature.
//! 3. Providing our own `RpcClientT` impl and client constructor here.

use crate::error::{HermesError, Result};
use jsonrpsee::core::client::{
    Client, ClientBuilder, ClientT, SubscriptionClientT, SubscriptionKind,
};
use jsonrpsee::core::traits::ToRpcParams;
use serde_json::value::RawValue;
use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RpcClient, RpcClientT};
use subxt::ext::futures::{StreamExt, TryStreamExt};
use subxt::{OnlineClient, PolkadotConfig};

struct Params(Option<Box<RawValue>>);

impl ToRpcParams for Params {
    fn to_rpc_params(self) -> std::result::Result<Option<Box<RawValue>>, serde_json::Error> {
        Ok(self.0)
    }
}

/// Wrapper to implement subxt's `RpcClientT` for a jsonrpsee `Client`.
///
/// This mirrors subxt's own impl (behind `cfg(feature = "jsonrpsee")`),
/// but compiled without activating native-tls on jsonrpsee.
struct JsonrpseeClient(Client);

impl RpcClientT for JsonrpseeClient {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        Box::pin(async move {
            let res = ClientT::request(&self.0, method, Params(params))
                .await
                .map_err(|e| subxt::error::RpcError::ClientError(Box::new(e)))?;
            Ok(res)
        })
    }

    fn subscribe_raw<'a>(
        &'a self,
        sub: &'a str,
        params: Option<Box<RawValue>>,
        unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async move {
            let stream = SubscriptionClientT::subscribe::<Box<RawValue>, _>(
                &self.0,
                sub,
                Params(params),
                unsub,
            )
            .await
            .map_err(|e| subxt::error::RpcError::ClientError(Box::new(e)))?;

            let id = match stream.kind() {
                SubscriptionKind::Subscription(sub_id) => {
                    // SubscriptionId doesn't impl Display; serialize to extract the inner value.
                    serde_json::to_value(sub_id).ok().and_then(|v| match v {
                        serde_json::Value::String(s) => Some(s),
                        serde_json::Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                }
                _ => None,
            };

            let stream = stream
                .map_err(|e| subxt::error::RpcError::ClientError(Box::new(e)))
                .boxed();
            Ok(RawRpcSubscription { stream, id })
        })
    }
}

/// Connect to a Substrate node via WebSocket using rustls (no openssl dependency).
pub async fn connect(rpc_url: &str) -> Result<OnlineClient<PolkadotConfig>> {
    use jsonrpsee::client_transport::ws::{Url, WsTransportClientBuilder};

    let url = Url::parse(rpc_url)
        .map_err(|e| HermesError::Identity(format!("Invalid RPC URL '{}': {}", rpc_url, e)))?;

    let (sender, receiver) = WsTransportClientBuilder::default()
        .build(url)
        .await
        .map_err(|e| {
            HermesError::Identity(format!(
                "Failed to establish WebSocket connection to {}: {}",
                rpc_url, e
            ))
        })?;

    let client = ClientBuilder::default()
        .max_buffer_capacity_per_subscription(4096)
        .build_with_tokio(sender, receiver);

    let rpc_client = RpcClient::new(JsonrpseeClient(client));

    OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client)
        .await
        .map_err(|e| {
            HermesError::Identity(format!(
                "Failed to initialize subxt OnlineClient from {}: {}",
                rpc_url, e
            ))
        })
}
