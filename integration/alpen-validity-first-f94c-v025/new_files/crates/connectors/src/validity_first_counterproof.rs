//! Validity-first counterproof connector.
//!
//! A valid positive RankLock evaluation releases a 32-byte preimage and enables
//! the immediate ACK leaf.  If no valid preimage spend confirms, a pre-signed
//! N/N transaction can take the CSV-delayed NACK leaf.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes, relative, script, Amount, Network, ScriptBuf, Sequence,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_crypto::keys::constants::UNSPENDABLE_PUBLIC_KEY;

use crate::{Connector, TaprootWitness};

/// Taproot connector between a watchtower counterproof and its ACK/NACK race.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidityFirstCounterproofConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    ack_preimage_hash: [u8; 32],
    nack_timelock: relative::Height,
    value: Amount,
}

impl ValidityFirstCounterproofConnector {
    /// Creates a connector. `surcharge` funds the larger of the two fixed
    /// downstream transactions so neither branch depends on a fee wallet.
    pub fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        ack_preimage_hash: [u8; 32],
        nack_timelock: relative::Height,
        surcharge: Amount,
    ) -> Self {
        let mut connector = Self {
            network,
            n_of_n_pubkey,
            ack_preimage_hash,
            nack_timelock,
            value: Amount::ZERO,
        };
        connector.value = connector.script_pubkey().minimal_non_dust() + surcharge;
        connector
    }

    /// Hash committed by the immediate ACK leaf.
    pub const fn ack_preimage_hash(&self) -> [u8; 32] {
        self.ack_preimage_hash
    }

    /// CSV delay of the default NACK branch.
    pub const fn nack_timelock(&self) -> relative::Height {
        self.nack_timelock
    }

    /// Returns true only for the exact 32-byte RankLock unlock value.
    pub fn accepts_preimage(&self, preimage: &[u8; 32]) -> bool {
        sha256::Hash::hash(preimage).to_byte_array() == self.ack_preimage_hash
    }
}

impl Connector for ValidityFirstCounterproofConnector {
    type SpendPath = ValidityFirstCounterproofSpendPath;
    type Witness = ValidityFirstCounterproofWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        *UNSPENDABLE_PUBLIC_KEY
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        // Witness stack for this leaf is [preimage, n-of-n signature].
        // CHECKSIGVERIFY consumes the signature and pubkey first, leaving the
        // preimage for SHA256.
        let ack = script::Builder::new()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(self.ack_preimage_hash)
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();

        let nack = script::Builder::new()
            .push_sequence(Sequence::from_height(self.nack_timelock.value()))
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        vec![ack, nack]
    }

    fn value(&self) -> Amount {
        self.value
    }

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        Some(match spend_path {
            ValidityFirstCounterproofSpendPath::Ack => 0,
            ValidityFirstCounterproofSpendPath::NackTimeout => 1,
        })
    }

    fn sequence(&self, spend_path: Self::SpendPath) -> Sequence {
        match spend_path {
            ValidityFirstCounterproofSpendPath::Ack => Sequence::MAX,
            ValidityFirstCounterproofSpendPath::NackTimeout => {
                Sequence::from_height(self.nack_timelock.value())
            }
        }
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            ValidityFirstCounterproofWitness::Ack {
                n_of_n_signature,
                preimage,
            } => TaprootWitness::Script {
                leaf_index: 0,
                script_inputs: vec![preimage.to_vec(), n_of_n_signature.serialize().to_vec()],
            },
            ValidityFirstCounterproofWitness::NackTimeout { n_of_n_signature } => {
                TaprootWitness::Script {
                    leaf_index: 1,
                    script_inputs: vec![n_of_n_signature.serialize().to_vec()],
                }
            }
        }
    }
}

/// Available spends of [`ValidityFirstCounterproofConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValidityFirstCounterproofSpendPath {
    /// Immediate valid-counterproof ACK, unlocked by the RankLock preimage.
    Ack,
    /// CSV-delayed default NACK, authorized by the pre-signed N/N key.
    NackTimeout,
}

/// Witnesses for [`ValidityFirstCounterproofConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValidityFirstCounterproofWitness {
    /// Immediate ACK witness.
    Ack {
        /// Exact-message N/N signature for the ACK transaction.
        n_of_n_signature: schnorr::Signature,
        /// Positive-lock preimage released only for a valid counterproof.
        preimage: [u8; 32],
    },
    /// Timeout NACK witness.
    NackTimeout {
        /// Exact-message N/N signature for the fixed timeout transaction.
        n_of_n_signature: schnorr::Signature,
    },
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute,
        sighash::{Prevouts, SighashCache},
        transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Witness,
    };
    use secp256k1::{rand::random, schnorr, Keypair};
    use strata_bridge_primitives::scripts::prelude::create_tx_ins;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{
        test_utils::{BitcoinNode, Signer},
        Connector, SigningInfo,
    };

    const TIMELOCK: relative::Height = relative::Height::from_height(5);
    const TEST_FEE: Amount = Amount::from_sat(1_000);

    struct ValidityFirstSigner {
        n_of_n_keypair: Keypair,
        preimage: [u8; 32],
    }

    impl Signer for ValidityFirstSigner {
        type Connector = ValidityFirstCounterproofConnector;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                preimage: random(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            connector_for(&self.n_of_n_keypair, self.preimage)
        }

        fn get_connector_name(&self) -> &'static str {
            "validity-first-counterproof"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            let signature = signing_info.sign(&self.n_of_n_keypair);
            match spend_path {
                ValidityFirstCounterproofSpendPath::Ack => ValidityFirstCounterproofWitness::Ack {
                    n_of_n_signature: signature,
                    preimage: self.preimage,
                },
                ValidityFirstCounterproofSpendPath::NackTimeout => {
                    ValidityFirstCounterproofWitness::NackTimeout {
                        n_of_n_signature: signature,
                    }
                }
            }
        }
    }

    fn connector_for(
        n_of_n_keypair: &Keypair,
        preimage: [u8; 32],
    ) -> ValidityFirstCounterproofConnector {
        ValidityFirstCounterproofConnector::new(
            Network::Regtest,
            n_of_n_keypair.x_only_public_key().0,
            sha256::Hash::hash(&preimage).to_byte_array(),
            TIMELOCK,
            TEST_FEE,
        )
    }

    fn fund_connector(
        node: &mut BitcoinNode,
        connector: ValidityFirstCounterproofConnector,
    ) -> OutPoint {
        let funding_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: create_tx_ins([node.next_coinbase_outpoint()]),
            output: vec![
                connector.tx_out(),
                TxOut {
                    value: node.coinbase_amount() - connector.value() - TEST_FEE,
                    script_pubkey: node.wallet_address().script_pubkey(),
                },
            ],
        };
        let txid = node.sign_and_broadcast(&funding_tx);
        node.mine_blocks(1);
        OutPoint::new(txid, 0)
    }

    fn ack_template(
        node: &mut BitcoinNode,
        connector: ValidityFirstCounterproofConnector,
        connector_outpoint: OutPoint,
    ) -> (Transaction, [TxOut; 2]) {
        let mut tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: create_tx_ins([connector_outpoint, node.next_coinbase_outpoint()]),
            output: vec![TxOut {
                value: node.coinbase_amount() + connector.value() - TEST_FEE,
                script_pubkey: node.wallet_address().script_pubkey(),
            }],
        };
        tx.input[0].sequence = connector.sequence(ValidityFirstCounterproofSpendPath::Ack);
        let prevouts = [connector.tx_out(), node.coinbase_tx_out()];
        (tx, prevouts)
    }

    fn ack_signature(
        tx: &Transaction,
        prevouts: &[TxOut; 2],
        connector: ValidityFirstCounterproofConnector,
        keypair: &Keypair,
    ) -> schnorr::Signature {
        let mut cache = SighashCache::new(tx);
        connector
            .get_signing_info(
                &mut cache,
                Prevouts::All(prevouts),
                ValidityFirstCounterproofSpendPath::Ack,
                0,
            )
            .sign(keypair)
    }

    fn finalize_ack(
        node: &BitcoinNode,
        tx: Transaction,
        prevouts: [TxOut; 2],
        connector: ValidityFirstCounterproofConnector,
        signature: schnorr::Signature,
        preimage: [u8; 32],
    ) -> Transaction {
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");
        psbt.inputs[0].witness_utxo = Some(prevouts[0].clone());
        psbt.inputs[1].witness_utxo = Some(prevouts[1].clone());
        connector.finalize_input(
            &mut psbt.inputs[0],
            &ValidityFirstCounterproofWitness::Ack {
                n_of_n_signature: signature,
                preimage,
            },
        );
        let partially_signed = psbt.extract_tx().expect("should extract transaction");
        node.sign(&partially_signed)
    }

    #[test]
    fn immediate_ack_spend() {
        ValidityFirstSigner::assert_connector_is_spendable(ValidityFirstCounterproofSpendPath::Ack);
    }

    #[test]
    fn timeout_nack_spend() {
        ValidityFirstSigner::assert_connector_is_spendable(
            ValidityFirstCounterproofSpendPath::NackTimeout,
        );
    }

    #[test]
    fn preimage_commitment_is_exact() {
        let signer = ValidityFirstSigner::generate();
        let connector = signer.get_connector();
        assert!(connector.accepts_preimage(&signer.preimage));
        let mut wrong = signer.preimage;
        wrong[0] ^= 1;
        assert!(!connector.accepts_preimage(&wrong));
    }

    #[test]
    fn alternate_context_preimage_is_rejected_by_core() {
        let mut node = BitcoinNode::new();
        let keypair = generate_keypair();
        let preimage_a: [u8; 32] = random();
        let mut preimage_b: [u8; 32] = random();
        while preimage_b == preimage_a {
            preimage_b = random();
        }
        let connector_b = connector_for(&keypair, preimage_b);
        let outpoint_b = fund_connector(&mut node, connector_b);
        let (tx_b, prevouts_b) = ack_template(&mut node, connector_b, outpoint_b);
        let signature_b = ack_signature(&tx_b, &prevouts_b, connector_b, &keypair);
        let wrong_context = finalize_ack(
            &node,
            tx_b,
            prevouts_b,
            connector_b,
            signature_b,
            preimage_a,
        );
        assert!(
            node.client().send_raw_transaction(&wrong_context).is_err(),
            "Core accepted a preimage committed by another game/deposit context"
        );
    }

    #[test]
    fn exact_message_signature_replay_is_rejected_by_core() {
        let mut node = BitcoinNode::new();
        let keypair = generate_keypair();
        let preimage: [u8; 32] = random();
        let connector = connector_for(&keypair, preimage);

        let outpoint_a = fund_connector(&mut node, connector);
        let (tx_a, prevouts_a) = ack_template(&mut node, connector, outpoint_a);
        let signature_a = ack_signature(&tx_a, &prevouts_a, connector, &keypair);

        let outpoint_b = fund_connector(&mut node, connector);
        let (tx_b, prevouts_b) = ack_template(&mut node, connector, outpoint_b);
        let replay = finalize_ack(&node, tx_b, prevouts_b, connector, signature_a, preimage);
        assert!(
            node.client().send_raw_transaction(&replay).is_err(),
            "Core accepted an N/N signature copied from another exact ACK template"
        );
    }

    #[test]
    fn malformed_positive_unlock_is_rejected_by_core() {
        let mut node = BitcoinNode::new();
        let keypair = generate_keypair();
        let preimage: [u8; 32] = random();
        let connector = connector_for(&keypair, preimage);
        let outpoint = fund_connector(&mut node, connector);
        let (tx, prevouts) = ack_template(&mut node, connector, outpoint);
        let signature = ack_signature(&tx, &prevouts, connector, &keypair);
        let mut malformed = finalize_ack(&node, tx, prevouts, connector, signature, preimage);
        let mut witness_items = malformed.input[0].witness.to_vec();
        witness_items[0].pop();
        malformed.input[0].witness = Witness::from_slice(&witness_items);
        assert!(
            node.client().send_raw_transaction(&malformed).is_err(),
            "Core accepted a 31-byte positive-lock witness"
        );
    }
}
