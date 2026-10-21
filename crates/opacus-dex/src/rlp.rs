//! Minimal RLP encoding (Ethereum legacy transactions).

/// An RLP-encodable value.
#[derive(Clone, Debug)]
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        RlpItem::Bytes(b.into())
    }

    /// Encode a big-endian unsigned integer without leading zeros.
    pub fn uint(be: &[u8]) -> Self {
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        RlpItem::Bytes(be[first..].to_vec())
    }

    pub fn list(items: Vec<RlpItem>) -> Self {
        RlpItem::List(items)
    }

    /// Full RLP encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RlpItem::Bytes(b) => encode_scalar(b),
            RlpItem::List(items) => {
                let payload: Vec<u8> = items.iter().flat_map(|i| i.encode()).collect();
                let mut out = encode_length(payload.len(), 0xc0);
                out.extend_from_slice(&payload);
                out
            }
        }
    }
}

/// RLP-encode a byte string.
fn encode_scalar(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = encode_length(b.len(), 0x80);
    out.extend_from_slice(b);
    out
}

fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len <= 55 {
        vec![offset + len as u8]
    } else {
        let len_bytes = len.to_be_bytes();
        let first = len_bytes.iter().position(|&b| b != 0).unwrap();
        let significant = &len_bytes[first..];
        let mut out = vec![offset + 55 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

/// 32-byte big-endian helper for amounts.
pub fn u256_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// 32-byte big-endian helper for u128 (token amounts).
pub fn u256_from_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // "" -> 0x80
        assert_eq!(RlpItem::bytes(Vec::<u8>::new()).encode(), vec![0x80]);
        // "dog" -> 0x83 646f67
        assert_eq!(
            RlpItem::bytes(b"dog".to_vec()).encode(),
            vec![0x83, b'd', b'o', b'g']
        );
        // 0 -> 0x80
        assert_eq!(RlpItem::uint(&u256_from_u64(0)).encode(), vec![0x80]);
        // 1024 -> 0x82 0400
        assert_eq!(
            RlpItem::uint(&u256_from_u64(1024)).encode(),
            vec![0x82, 0x04, 0x00]
        );
        // ["cat", "dog"] -> 0xc8 83 636174 83 646f67
        assert_eq!(
            RlpItem::list(vec![
                RlpItem::bytes(b"cat".to_vec()),
                RlpItem::bytes(b"dog".to_vec()),
            ])
            .encode(),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        // 56-bit length boundary: a 56-byte string uses long form
        let long = vec![0u8; 56];
        let enc = RlpItem::bytes(long).encode();
        assert_eq!(enc[0], 0xb8);
        assert_eq!(enc[1], 56);
        assert_eq!(enc.len(), 58);
    }
}
