//! Ethereum JSON-RPC client (read calls + raw tx broadcast) over a pluggable
//! transport. The default HTTP transport uses `ureq`.

use crate::tx::Address;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug)]
pub enum EthError {
    Rpc(String),
    Transport(String),
    BadResponse(String),
}

impl std::fmt::Display for EthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthError::Rpc(m) => write!(f, "rpc error: {m}"),
            EthError::Transport(m) => write!(f, "transport error: {m}"),
            EthError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

impl std::error::Error for EthError {}

/// Transport-agnostic JSON-RPC call.
pub trait Transport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, EthError>;
}

/// Minimal HTTP transport via ureq (rustls, no OpenSSL needed).
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn post(&self, url: &str, body: &Value) -> Result<Value, EthError> {
        let resp = ureq::post(url)
            .send_json(body.clone())
            .map_err(|e| EthError::Transport(e.to_string()))?;
        resp.into_json::<Value>()
            .map_err(|e| EthError::BadResponse(e.to_string()))
    }
}

/// Ethereum JSON-RPC client.
pub struct EthClient<T: Transport = HttpTransport> {
    pub url: String,
    pub transport: T,
    pub next_id: std::cell::Cell<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcEnvelope {
    id: u64,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

impl<T: Transport> EthClient<T> {
    pub fn with_transport(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, EthError> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let resp = self.transport.post(&self.url, &body)?;
        let env: RpcEnvelope =
            serde_json::from_value(resp).map_err(|e| EthError::BadResponse(e.to_string()))?;
        if let Some(err) = env.error {
            return Err(EthError::Rpc(err.to_string()));
        }
        env.result
            .ok_or_else(|| EthError::BadResponse("missing result".into()))
    }

    /// eth_call: read-only execution of `data` against `to`.
    pub fn eth_call(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, EthError> {
        let res = self.call(
            "eth_call",
            json!([
                {"to": to.to_hex(), "data": format!("0x{}", hex::encode(data))},
                "latest"
            ]),
        )?;
        let s = res
            .as_str()
            .ok_or_else(|| EthError::BadResponse("eth_call: not a string".into()))?;
        hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|e| EthError::BadResponse(format!("hex: {e}")))
    }

    /// eth_gasPrice -> wei as u128.
    pub fn gas_price(&self) -> Result<u128, EthError> {
        let res = self.call("eth_gasPrice", json!([]))?;
        parse_qty(&res)
    }

    /// eth_getTransactionCount (pending) -> nonce.
    pub fn nonce(&self, address: Address) -> Result<u64, EthError> {
        let res = self.call(
            "eth_getTransactionCount",
            json!([address.to_hex(), "pending"]),
        )?;
        parse_qty(&res).map(|v| v as u64)
    }

    /// eth_estimateGas for a call envelope.
    pub fn estimate_gas(
        &self,
        from: Address,
        call: &crate::uniswap::Call,
    ) -> Result<u64, EthError> {
        let res = self.call(
            "eth_estimateGas",
            json!([{
                "from": from.to_hex(),
                "to": call.to.to_hex(),
                "data": format!("0x{}", hex::encode(&call.data)),
                "value": format!("0x{}", hex::encode(strip_leading_zeros(&call.value_wei))),
            }]),
        )?;
        parse_qty(&res).map(|v| v as u64)
    }

    /// eth_sendRawTransaction.
    pub fn send_raw_transaction(&self, raw_hex: &str) -> Result<String, EthError> {
        let res = self.call("eth_sendRawTransaction", json!([raw_hex]))?;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| EthError::BadResponse("sendRawTransaction: not a string".into()))
    }
}

fn parse_qty(v: &Value) -> Result<u128, EthError> {
    let s = v
        .as_str()
        .ok_or_else(|| EthError::BadResponse("expected qty hex string".into()))?;
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .map_err(|e| EthError::BadResponse(format!("qty: {e}")))
}

fn strip_leading_zeros(be: &[u8; 32]) -> &[u8] {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    if first == be.len() {
        &be[be.len() - 1..] // single zero byte
    } else {
        &be[first..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory transport with canned responses.
    struct FakeTransport {
        respond: Box<dyn Fn(&str, &Value) -> Value>,
    }

    impl Transport for FakeTransport {
        fn post(&self, _url: &str, body: &Value) -> Result<Value, EthError> {
            let method = body["method"].as_str().unwrap_or_default();
            Ok((self.respond)(method, body))
        }
    }

    #[test]
    fn eth_call_and_qty_parsing() {
        let transport = FakeTransport {
            respond: Box::new(|method, _| {
                let result = match method {
                    "eth_call" => {
                        "0x0000000000000000000000000000000000000000000000000000000000000064"
                    }
                    "eth_gasPrice" => "0x4a817c800",
                    _ => "0x0",
                };
                json!({"id": 1, "result": result})
            }),
        };
        let client = EthClient::with_transport("http://fake", transport);
        let out = client.eth_call(Address([1; 20]), &[0xde, 0xad]).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(out[31], 100);
        assert_eq!(client.gas_price().unwrap(), 20_000_000_000);
    }

    #[test]
    fn rpc_error_propagates() {
        let transport = FakeTransport {
            respond: Box::new(
                |_, _| json!({"id": 1, "error": {"code": -32000, "message": "execution reverted"}}),
            ),
        };
        let client = EthClient::with_transport("http://fake", transport);
        let err = client.eth_call(Address([1; 20]), &[]).unwrap_err();
        assert!(err.to_string().contains("execution reverted"));
    }
}
