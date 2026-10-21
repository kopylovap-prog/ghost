//! Light Wallet

use opacus_crypto::keys::SpendingKey;
use opacus_crypto::stealth::{PublicAddress, RecipientKeys};
use std::collections::{HashMap, HashSet};

use crate::zk_spend::{
    build_with_depth, fp_to_bytes, SpendInput, TreeState, WalletNote, ZkSpendError, ZkSpendTx,
};
use opacus_zk::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("Not synced")]
    NotSynced,
    #[error("Corrupt zk note bytes")]
    CorruptNote,
    #[error("zk error: {0}")]
    Zk(String),
}

impl From<ZkSpendError> for WalletError {
    fn from(e: ZkSpendError) -> Self {
        WalletError::Zk(e.to_string())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Balance {
    pub total: u64,
    pub spendable: u64,
    pub pending: u64,
}

#[derive(Clone, Debug)]
pub struct UnspentNote {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub onetime_privkey: [u8; 32],
    pub tree_position: u64,
}

/// A zk-native note tracked by this wallet.
#[derive(Clone, Debug)]
pub struct ZkTrackedNote {
    pub note: WalletNote,
    /// Position of the note commitment in the global Merkle tree.
    pub leaf_index: usize,
    pub spent: bool,
}

/// One payment instruction inside a shielded transaction.
///
/// `recipient_sk: None` means the output belongs to this wallet (change /
/// self-consolidation). `Some(sk)` means the note is bound to a recipient's
/// derived one-time secret; the wallet publishes its commitment and forgets
/// it (the recipient learns `sk` out-of-band / via the network's note
/// encryption, which arrives with the networking phase).
#[derive(Clone, Debug)]
pub struct ZkPayment {
    pub value: u64,
    pub recipient_sk: Option<[u8; 32]>,
}

/// Result of building a shielded transaction: the signed-off zk spend plus
/// the wallet's own output notes, which become spendable after
/// [`LightWallet::confirm_zk_tx`] (mirrors the consensus confirm step).
#[derive(Clone, Debug)]
pub struct ZkSpendReceipt {
    pub tx: ZkSpendTx,
    pub own_outputs: Vec<WalletNote>,
}

pub struct LightWallet {
    keys: RecipientKeys,
    address: String,
    unspent_notes: HashMap<[u8; 32], UnspentNote>,
    balance: Balance,
    /// The wallet's mirror of the global note-commitment tree.
    zk_tree: TreeState,
    zk_notes: HashMap<[u8; 32], ZkTrackedNote>,
    zk_seen_nullifiers: HashSet<[u8; 32]>,
}

impl LightWallet {
    pub fn new(spending_key: &SpendingKey) -> Self {
        Self::new_with_tree_depth(spending_key, TREE_DEPTH_MAINNET)
    }

    /// Constructor with a configurable tree depth (testnets / tests).
    pub fn new_with_tree_depth(spending_key: &SpendingKey, depth: usize) -> Self {
        let keys = RecipientKeys {
            view_key: spending_key.view_key,
            spend_key: spending_key.spend_key,
        };
        let address = PublicAddress::from_keys(&keys).to_string();
        Self {
            keys,
            address,
            unspent_notes: HashMap::new(),
            balance: Balance::default(),
            zk_tree: TreeState::new(depth),
            zk_notes: HashMap::new(),
            zk_seen_nullifiers: HashSet::new(),
        }
    }

    pub fn get_address(&self) -> &str { &self.address }
    pub fn get_balance(&self) -> &Balance { &self.balance }

    pub fn add_note(&mut self, note: UnspentNote) {
        self.balance.total += note.amount;
        self.balance.spendable += note.amount;
        self.unspent_notes.insert(note.commitment, note);
    }

    // ------------------------------------------------------------------
    // zk (shielded) layer
    // ------------------------------------------------------------------

    /// Current root of the wallet's note-commitment tree.
    pub fn zk_root(&self) -> Fp {
        self.zk_tree.root()
    }

    /// Number of real leaves in the wallet's tree.
    pub fn zk_leaves(&self) -> usize {
        self.zk_tree.len()
    }

    /// Sum of unspent shielded notes.
    pub fn zk_balance(&self) -> u64 {
        self.zk_notes.values().filter(|t| !t.spent).map(|t| t.note.value).sum()
    }

    /// `(total_tracked, spent)` zk note counts.
    pub fn zk_note_counts(&self) -> (usize, usize) {
        let spent = self.zk_notes.values().filter(|t| t.spent).count();
        (self.zk_notes.len(), spent)
    }

    /// Whether a nullifier has already been published by this wallet.
    pub fn is_nullifier_seen(&self, nf: Fp) -> bool {
        self.zk_seen_nullifiers.contains(&fp_to_bytes(nf))
    }

    /// Track an incoming (or locally minted) shielded note: append its
    /// commitment to the tree and credit the balance.
    pub fn add_zk_note(&mut self, note: WalletNote) -> Result<usize, WalletError> {
        let cm = note.commitment().ok_or(WalletError::CorruptNote)?;
        let idx = self.zk_tree.append(cm);
        let value = note.value;
        self.zk_notes.insert(
            fp_to_bytes(cm),
            ZkTrackedNote {
                note,
                leaf_index: idx,
                spent: false,
            },
        );
        self.balance.total += value;
        self.balance.spendable += value;
        Ok(idx)
    }

    /// Convenience for incoming transfers: build the note from raw secrets.
    pub fn confirm_incoming_note(
        &mut self,
        sk: [u8; 32],
        rho: [u8; 32],
        value: u64,
    ) -> Result<usize, WalletError> {
        self.add_zk_note(WalletNote { sk, rho, value })
    }

    /// Build and prove a mainnet-depth shielded transaction (one input note,
    /// many outputs). See [`Self::build_zk_spend_with_depth`].
    pub fn build_zk_spend(
        &mut self,
        payments: &[ZkPayment],
    ) -> Result<ZkSpendReceipt, WalletError> {
        self.build_zk_spend_with_depth::<TREE_DEPTH_MAINNET>(payments)
    }

    /// Build and prove a shielded transaction against a tree of depth
    /// `DEPTH` (must match the wallet's tree depth).
    ///
    /// Selection is naive: the first unspent note covering `sum(values)`.
    /// The transaction is verified immediately; only after a successful
    /// proof is the input note marked spent and its nullifier recorded.
    pub fn build_zk_spend_with_depth<const DEPTH: usize>(
        &mut self,
        payments: &[ZkPayment],
    ) -> Result<ZkSpendReceipt, WalletError> {
        if self.zk_tree.depth() != DEPTH {
            return Err(WalletError::Zk(format!(
                "tree depth {} does not match DEPTH {}",
                self.zk_tree.depth(),
                DEPTH
            )));
        }
        let needed: u64 = payments.iter().map(|p| p.value).sum();
        if needed == 0 {
            return Err(WalletError::Zk("empty payment list".into()));
        }
        let picked = self
            .zk_notes
            .iter()
            .find(|(_, t)| !t.spent && t.note.value >= needed)
            .map(|(cm, t)| (*cm, t.note.clone(), t.leaf_index))
            .ok_or(WalletError::InsufficientFunds {
                needed,
                available: self.zk_balance(),
            })?;
        let (cm_key, input_note, leaf_index) = picked;
        let input_value = input_note.value;

        let mut outputs = Vec::with_capacity(payments.len());
        for p in payments {
            let sk = p.recipient_sk.unwrap_or_else(|| fp_to_bytes(Fp::random(OsRng)));
            let rho = fp_to_bytes(Fp::random(OsRng));
            outputs.push(WalletNote {
                sk,
                rho,
                value: p.value,
            });
        }

        let spend_input = SpendInput {
            note: input_note,
            leaf_index,
        };
        let tx = build_with_depth::<DEPTH>(&self.zk_tree, &spend_input, &outputs)?;
        // Self-check: never mutate wallet state on an unverifiable tx.
        tx.verify_with_depth::<DEPTH>()?;

        if let Some(t) = self.zk_notes.get_mut(&cm_key) {
            t.spent = true;
        }
        self.zk_seen_nullifiers.insert(fp_to_bytes(tx.nullifier));

        let own_outputs: Vec<WalletNote> = payments
            .iter()
            .zip(outputs.iter())
            .filter(|(p, _)| p.recipient_sk.is_none())
            .map(|(_, o)| o.clone())
            .collect();
        let own_change: u64 = own_outputs.iter().map(|o| o.value).sum();

        self.balance.spendable = self.balance.spendable.saturating_sub(input_value);
        self.balance.pending += own_change;

        Ok(ZkSpendReceipt { tx, own_outputs })
    }

    /// Confirm a built transaction: append every output commitment to the
    /// tree (mirroring consensus order) and make our own outputs spendable.
    pub fn confirm_zk_tx(&mut self, receipt: &ZkSpendReceipt) -> Result<(), WalletError> {
        let base = self.zk_tree.len();
        for cm in &receipt.tx.output_commitments {
            self.zk_tree.append(*cm);
        }
        for note in &receipt.own_outputs {
            let cm = note.commitment().ok_or(WalletError::CorruptNote)?;
            let pos = receipt
                .tx
                .output_commitments
                .iter()
                .position(|c| c == &cm)
                .ok_or(WalletError::CorruptNote)?;
            self.zk_notes.insert(
                fp_to_bytes(cm),
                ZkTrackedNote {
                    note: note.clone(),
                    leaf_index: base + pos,
                    spent: false,
                },
            );
        }
        let own_change: u64 = receipt.own_outputs.iter().map(|o| o.value).sum();
        self.balance.pending = self.balance.pending.saturating_sub(own_change);
        self.balance.spendable += own_change;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet(depth: usize) -> LightWallet {
        let sk = SpendingKey {
            spend_key: [7u8; 32],
            view_key: [9u8; 32],
            mnemonic: "test wallet".into(),
        };
        LightWallet::new_with_tree_depth(&sk, depth)
    }

    #[test]
    fn zk_notes_track_balance() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(100)).unwrap();
        w.add_zk_note(WalletNote::random(50)).unwrap();
        assert_eq!(w.zk_balance(), 150);
        assert_eq!(w.get_balance().total, 150);
        assert_eq!(w.zk_leaves(), 2);
        assert_eq!(w.zk_note_counts(), (2, 0));
    }

    #[test]
    fn zk_spend_change_flow_depth4() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(100)).unwrap();
        w.add_zk_note(WalletNote::random(50)).unwrap();

        let recipient_sk = fp_to_bytes(Fp::random(OsRng));
        let payments = vec![
            ZkPayment {
                value: 30,
                recipient_sk: Some(recipient_sk),
            },
            ZkPayment {
                value: 70,
                recipient_sk: None, // change back to us
            },
        ];
        let receipt = w.build_zk_spend_with_depth::<4>(&payments).expect("build");

        // Input burned immediately, change pending until confirmation.
        assert_eq!(w.zk_balance(), 50);
        assert_eq!(w.get_balance().spendable, 50);
        assert_eq!(w.get_balance().pending, 70);
        assert!(w.is_nullifier_seen(receipt.tx.nullifier));
        assert_eq!(receipt.tx.output_commitments.len(), 2);
        assert_eq!(w.zk_note_counts(), (2, 1));

        // Confirm mirrors consensus: outputs enter the tree, change spendable.
        w.confirm_zk_tx(&receipt).unwrap();
        assert_eq!(w.zk_balance(), 120);
        assert_eq!(w.get_balance().pending, 0);
        assert_eq!(w.get_balance().total, 150);
        assert_eq!(w.zk_leaves(), 4);

        // Incoming external note credits the wallet.
        w.confirm_incoming_note([3u8; 32], [4u8; 32], 500).unwrap();
        assert_eq!(w.zk_balance(), 620);

        // No single unspent note covers 800 (max is the 500-incoming note;
        // the spent 100-note is skipped even though balance totals 620).
        let res = w.build_zk_spend_with_depth::<4>(&[ZkPayment {
            value: 800,
            recipient_sk: None,
        }]);
        assert!(matches!(
            res,
            Err(WalletError::InsufficientFunds { needed: 800, .. })
        ));

        // Recipient's note is bound to their secret, not ours.
        let own = WalletNote {
            sk: recipient_sk,
            rho: [5u8; 32],
            value: 30,
        };
        assert_ne!(own.commitment().unwrap(), Fp::ZERO);
    }

    #[test]
    fn zk_insufficient_funds() {
        let mut w = test_wallet(4);
        w.add_zk_note(WalletNote::random(10)).unwrap();
        let res = w.build_zk_spend_with_depth::<4>(&[ZkPayment {
            value: 11,
            recipient_sk: None,
        }]);
        assert!(matches!(
            res,
            Err(WalletError::InsufficientFunds {
                needed: 11,
                available: 10
            })
        ));
    }

    #[test]
    #[ignore = "slow: full mainnet-depth (2^32) IPA proof"]
    fn zk_spend_mainnet_e2e() {
        let mut w = test_wallet(TREE_DEPTH_MAINNET);
        w.add_zk_note(WalletNote::random(1000)).unwrap();
        let receipt = w
            .build_zk_spend(&[
                ZkPayment {
                    value: 400,
                    recipient_sk: None,
                },
                ZkPayment {
                    value: 600,
                    recipient_sk: None,
                },
            ])
            .expect("mainnet build");
        receipt.tx.verify_mainnet().expect("mainnet verify");
        w.confirm_zk_tx(&receipt).unwrap();
        assert_eq!(w.zk_balance(), 1000);
        assert_eq!(w.zk_leaves(), 3);
    }
}
