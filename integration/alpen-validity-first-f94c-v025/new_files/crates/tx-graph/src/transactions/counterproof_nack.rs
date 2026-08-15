//! Fixed, pre-signed timeout NACK for the validity-first counterproof graph.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    OutPoint, Psbt, Transaction, TxIn, TxOut, Txid,
};
use bitcoin_bosd::Descriptor;
use secp256k1::schnorr;
use strata_bridge_connectors::{
    prelude::{
        ValidityFirstCounterproofConnector, ValidityFirstCounterproofSpendPath,
        ValidityFirstCounterproofWitness,
    },
    Connector, ParentTxCombined, SigningInfo,
};

use crate::transactions::{prelude::CounterproofTx, PresignedTx};

/// Data needed to construct a [`ValidityFirstCounterproofNackTx`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ValidityFirstCounterproofNackData {
    /// ID of the counterproof transaction whose ACK/NACK output is spent.
    pub counterproof_txid: Txid,
}

/// Deterministic CSV-delayed NACK transaction.
///
/// The sole output belongs to the graph owner and doubles as a CPFP-able
/// output. The transaction is N/N pre-signed at graph setup, so timeout
/// liveness does not require an online signer or Mosaic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidityFirstCounterproofNackTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    counterproof_connector: ValidityFirstCounterproofConnector,
}

impl ValidityFirstCounterproofNackTx {
    /// Index of the owner payout/CPFP output.
    pub const PAYOUT_VOUT: u32 = 0;
    /// Number of inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates the fixed timeout NACK transaction.
    pub fn new(
        data: ValidityFirstCounterproofNackData,
        counterproof_connector: ValidityFirstCounterproofConnector,
        operator_descriptor: &Descriptor,
    ) -> Self {
        let fee = crate::fee::validity_first_counterproof_nack_fee(
            counterproof_connector.nack_timelock(),
        );
        let prevouts = [counterproof_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.counterproof_txid,
                vout: CounterproofTx::ACK_NACK_VOUT,
            },
            sequence: counterproof_connector
                .sequence(ValidityFirstCounterproofSpendPath::NackTimeout),
            ..Default::default()
        }];
        let output = vec![TxOut {
            value: counterproof_connector
                .value()
                .checked_sub(fee)
                .expect("counterproof connector surcharge covers timeout NACK fee"),
            script_pubkey: operator_descriptor.to_script(),
        }];

        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");
        psbt.inputs[0].witness_utxo = Some(prevouts[0].clone());

        Self {
            psbt,
            prevouts,
            counterproof_connector,
        }
    }

    /// Finalizes the exact pre-signed timeout transaction.
    pub fn finalize(self, n_of_n_signature: schnorr::Signature) -> Transaction {
        let mut psbt = self.psbt;
        let witness = ValidityFirstCounterproofWitness::NackTimeout { n_of_n_signature };
        self.counterproof_connector
            .finalize_input(&mut psbt.inputs[0], &witness);
        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl ParentTxCombined for ValidityFirstCounterproofNackTx {
    type Index = ();

    fn cpfp_tx_out(&self, (): Self::Index) -> TxOut {
        self.psbt.unsigned_tx.output[Self::PAYOUT_VOUT as usize].clone()
    }

    fn cpfp_outpoint(&self, (): Self::Index) -> OutPoint {
        OutPoint {
            txid: self.psbt.unsigned_tx.compute_txid(),
            vout: Self::PAYOUT_VOUT,
        }
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for ValidityFirstCounterproofNackTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [self.counterproof_connector.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            ValidityFirstCounterproofSpendPath::NackTimeout,
            0,
        )]
    }
}

impl AsRef<Transaction> for ValidityFirstCounterproofNackTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
