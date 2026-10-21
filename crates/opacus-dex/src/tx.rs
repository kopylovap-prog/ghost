//! Ethereum legacy (EIP-155) transaction building and signing.

use crate::abi::keccak256;
use crate::rlp::RlpItem;
use k256::ecdsa::{SigningKey, VerifyingKey};

/// 20-byte Ethereum address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let b = hex::decode(s).ok()?;
        if b.len() != 20 {
            return None;
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&b);
        Some(Address(a))
    }
}

/// Address derived from a secp256k1 public key: keccak256(pubkey[1..65])[12..].
pub fn address_from_pubkey(pk: &VerifyingKey) -> Address {
    let encoded = pk.to_encoded_point(false); // 65 bytes, starts with 0x04
    let h = keccak256(&encoded.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Address(a)
}

/// Legacy transaction parameters.
#[derive(Clone, Debug)]
pub struct TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price_wei: u128,
    pub gas_limit: u64,
    /// `None` = contract creation.
    pub to: Option<Address>,
    /// Value in wei, big-endian 32 bytes.
    pub value_wei: [u8; 32],
    /// Calldata.
    pub data: Vec<u8>,
}

impl TxParams {
    /// The pre-image that is signed: RLP([nonce, gasPrice, gas, to, value,
    /// data, chainId, 0, 0]).
    fn signing_payload(&self) -> Vec<u8> {
        let to_item = match self.to {
            Some(a) => RlpItem::bytes(a.0.to_vec()),
            None => RlpItem::bytes(Vec::new()),
        };
        RlpItem::list(vec![
            RlpItem::uint(&crate::rlp::u256_from_u64(self.nonce)),
            RlpItem::uint(&crate::rlp::u256_from_u128(self.gas_price_wei)),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.gas_limit)),
            to_item,
            RlpItem::bytes(self.value_wei.to_vec()),
            RlpItem::bytes(self.data.clone()),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.chain_id)),
            RlpItem::uint(&[0u8; 32]),
            RlpItem::uint(&[0u8; 32]),
        ])
        .encode()
    }

    /// Signed raw transaction (0x-prefixed hex), EIP-155.
    pub fn sign(&self, sk: &SigningKey) -> Result<String, String> {
        let payload = self.signing_payload();
        let msg_hash = keccak256(&payload);

        // Deterministic ECDSA directly over the keccak prehash, with the
        // recovery id returned by the library (Signer::sign would apply
        // SHA-256 on top, which is NOT what Ethereum does).
        let (sig, recid) = sk
            .sign_prehash_recoverable(&msg_hash)
            .map_err(|e| e.to_string())?;

        // EIP-155: v = parity + 35 + 2 * chainId (no overflow recids after
        // canonical s normalization; both are tried anyway above).
        let parity = if recid.is_y_odd() { 1u64 } else { 0u64 };
        let v = parity + 35 + 2 * self.chain_id;

        let mut sig_r = [0u8; 32];
        sig_r.copy_from_slice(&sig.r().to_bytes()[..]);
        let mut sig_s = [0u8; 32];
        sig_s.copy_from_slice(&sig.s().to_bytes()[..]);

        let to_item = match self.to {
            Some(a) => RlpItem::bytes(a.0.to_vec()),
            None => RlpItem::bytes(Vec::new()),
        };
        let raw = RlpItem::list(vec![
            RlpItem::uint(&crate::rlp::u256_from_u64(self.nonce)),
            RlpItem::uint(&crate::rlp::u256_from_u128(self.gas_price_wei)),
            RlpItem::uint(&crate::rlp::u256_from_u64(self.gas_limit)),
            to_item,
            RlpItem::bytes(self.value_wei.to_vec()),
            RlpItem::bytes(self.data.clone()),
            RlpItem::uint(&crate::rlp::u256_from_u64(v)),
            RlpItem::bytes(sig_r.to_vec()),
            RlpItem::bytes(sig_s.to_vec()),
        ])
        .encode();

        Ok(format!("0x{}", hex::encode(&raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::RecoveryId;

    fn test_key(seed: u8) -> SigningKey {
        // Deterministic non-degenerate key for tests.
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_mul(7).max(1);
        SigningKey::from_bytes((&bytes).into()).unwrap()
    }

    #[test]
    fn address_roundtrip() {
        let sk = test_key(3);
        let addr = address_from_pubkey(sk.verifying_key());
        let hex_str = addr.to_hex();
        assert_eq!(hex_str.len(), 42);
        assert_eq!(Address::from_hex(&hex_str), Some(addr));
    }

    #[test]
    fn signed_tx_recovers_sender() {
        let sk = test_key(5);
        let sender = address_from_pubkey(sk.verifying_key());
        let tx = TxParams {
            chain_id: 1,
            nonce: 7,
            gas_price_wei: 30_000_000_000,
            gas_limit: 21000,
            to: Some(Address([0xee; 20])),
            value_wei: crate::rlp::u256_from_u128(1_000_000_000_000_000_000),
            data: vec![],
        };
        let raw = tx.sign(&sk).unwrap();
        assert!(raw.starts_with("0x"));
        let raw_bytes = hex::decode(&raw[2..]).unwrap();
        assert_eq!(raw_bytes[0] & 0xc0, 0xc0); // RLP list header (0xC0..0xFF)

        // Minimal RLP walker over the top-level list.
        fn read_item(bytes: &[u8], pos: &mut usize) -> Vec<u8> {
            let b = bytes[*pos];
            let (hdr_len, payload_len) = if b < 0x80 {
                (0usize, 1usize)
            } else if b <= 0xb7 {
                (1, (b - 0x80) as usize)
            } else if b <= 0xbf {
                let n = (b - 0xb7) as usize;
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | bytes[*pos + 1 + i] as usize;
                }
                (1 + n, len)
            } else if b <= 0xf7 {
                (1, (b - 0xc0) as usize)
            } else {
                let n = (b - 0xf7) as usize;
                let mut len = 0usize;
                for i in 0..n {
                    len = (len << 8) | bytes[*pos + 1 + i] as usize;
                }
                (1 + n, len)
            };
            let start = *pos + hdr_len;
            let payload = bytes[start..start + payload_len].to_vec();
            *pos = start + payload_len;
            payload
        }

        // Skip the list header: single byte (0xC0..0xF7) or multi-byte long
        // form (0xF8..0xFF followed by length bytes).
        let mut pos = if raw_bytes[0] <= 0xf7 {
            1
        } else {
            1 + (raw_bytes[0] - 0xf7) as usize
        };
        let items: Vec<Vec<u8>> = (0..9).map(|_| read_item(&raw_bytes, &mut pos)).collect();
        assert_eq!(pos, raw_bytes.len(), "consumed exactly the list payload");

        // v = item 6, r = 7, s = 8.
        let v = u64::from(items[6][0]);
        // EIP-155: v = parity + 35 + 2*chainId -> {37, 38} for chain_id=1.
        let parity = v - 35 - 2 * tx.chain_id;
        assert!(parity <= 1, "v={v} must satisfy EIP-155");
        assert_eq!(items[7].len(), 32, "r is 32-byte BE");
        assert_eq!(items[8].len(), 32, "s is 32-byte BE");

        // Recover the sender: hash the signing payload, recover pubkey.
        let msg_hash = keccak256(&tx.signing_payload());
        let mut r = [0u8; 32];
        r.copy_from_slice(&items[7]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&items[8]);
        let sig = k256::ecdsa::Signature::from_scalars(
            k256::FieldBytes::from(r),
            k256::FieldBytes::from(s),
        )
        .unwrap();
        let recid = RecoveryId::new(parity == 1, false);
        let vk = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recid).unwrap();
        assert_eq!(address_from_pubkey(&vk), sender);
    }

    #[test]
    fn deterministic_signature() {
        // RFC6979: same key + same payload -> same signature -> same raw tx.
        let sk = test_key(9);
        let tx = TxParams {
            chain_id: 137,
            nonce: 1,
            gas_price_wei: 200_000_000_000,
            gas_limit: 300_000,
            to: Some(Address([0x42; 20])),
            value_wei: [0u8; 32],
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let a = tx.sign(&sk).unwrap();
        let b = tx.sign(&sk).unwrap();
        assert_eq!(a, b);
    }
}
