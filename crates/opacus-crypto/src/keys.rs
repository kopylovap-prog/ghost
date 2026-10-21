//! Key management

use blake3::Hasher;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid mnemonic: need at least 12 words")]
    InvalidMnemonic,
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SpendingKey {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub mnemonic: String,
}

impl SpendingKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let h = hex::encode(entropy);
        let mnemonic = format!(
            "ghost {} {} {} {} {} {} {} {} {} {} {}",
            &h[0..6],
            &h[6..12],
            &h[12..18],
            &h[18..24],
            &h[24..30],
            &h[30..36],
            &h[36..42],
            &h[42..48],
            &h[48..54],
            &h[54..60],
            &h[60..64]
        );
        Self::from_mnemonic(&mnemonic).expect("valid generated mnemonic")
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, KeyError> {
        if mnemonic.split_whitespace().count() < 12 {
            return Err(KeyError::InvalidMnemonic);
        }
        let mut h = Hasher::new();
        h.update(b"ghost_spend_derive_v1");
        h.update(mnemonic.as_bytes());
        let spend: [u8; 32] = h.finalize().into();
        let mut h = Hasher::new();
        h.update(b"ghost_view_derive_v1");
        h.update(mnemonic.as_bytes());
        let view: [u8; 32] = h.finalize().into();
        Ok(Self {
            spend_key: spend,
            view_key: view,
            mnemonic: mnemonic.to_string(),
        })
    }
}
