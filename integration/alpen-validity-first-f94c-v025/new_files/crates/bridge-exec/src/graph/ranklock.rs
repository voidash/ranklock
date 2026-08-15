//! Narrow file-backed handoff between the bridge executor and RankLock.
//!
//! RankLock is deliberately kept out of the bridge process. At graph setup it
//! writes one 32-byte ACK commitment per `(graph owner, deposit index, game, watchtower)`.
//! After validating a concrete counterproof it writes the corresponding
//! 32-byte preimage. The bridge independently checks SHA256 before constructing
//! an ACK witness.

use std::{env, fs, io::ErrorKind, path::PathBuf};

use bitcoin::{
    hashes::{sha256, Hash},
    Transaction, Txid, XOnlyPublicKey,
};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::{GameIndex, GraphIdx, OperatorIdx};
use strata_bridge_tx_graph::transactions::prelude::CounterproofAckTx;
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

const ROOT_ENV: &str = "STRATA_RANKLOCK_DIR";

fn root() -> Result<PathBuf, ExecutorError> {
    env::var_os(ROOT_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| ExecutorError::RanklockErr(format!("{ROOT_ENV} is not configured")))
}

fn setup_name(
    graph_idx: GraphIdx,
    game_index: GameIndex,
    watchtower_idx: OperatorIdx,
) -> String {
    format!(
        "owner{}-deposit{}-game{}-watchtower{}.commitment",
        graph_idx.operator, graph_idx.deposit, game_index, watchtower_idx,
    )
}

fn unlock_name(
    bridge_proof_txid: Txid,
    counterproof_txid: Txid,
    counterproof_ack_txid: Txid,
) -> String {
    format!(
        "bridge{}-counterproof{}-ack{}.preimage",
        bridge_proof_txid, counterproof_txid, counterproof_ack_txid,
    )
}

fn decode_32(bytes: &[u8], label: &str) -> Result<[u8; 32], ExecutorError> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Ok(raw);
    }

    let text = std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| ExecutorError::RanklockErr(format!("{label} is neither raw nor UTF-8 hex")))?;
    if text.len() != 64 {
        return Err(ExecutorError::RanklockErr(format!(
            "{label} must contain exactly 32 raw bytes or 64 hex characters"
        )));
    }

    let mut decoded = [0u8; 32];
    for (idx, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("hex pair is UTF-8");
        decoded[idx] = u8::from_str_radix(pair, 16).map_err(|_| {
            ExecutorError::RanklockErr(format!("{label} contains malformed hexadecimal data"))
        })?;
    }
    Ok(decoded)
}

fn read_required(path: PathBuf, label: &str) -> Result<[u8; 32], ExecutorError> {
    let bytes = fs::read(&path).map_err(|err| {
        ExecutorError::RanklockErr(format!("failed to read {label} at {}: {err}", path.display()))
    })?;
    decode_32(&bytes, label)
}

/// Loads the setup-time positive-lock commitment.
///
/// The current P2P `fault_pubkeys` slot is reused byte-for-byte to avoid a graph
/// data migration. Therefore the commitment must be a valid x-only encoding;
/// the fixture/RankLock producer rejection-samples preimages until this holds.
pub(super) fn load_setup_commitment(
    graph_idx: GraphIdx,
    game_index: GameIndex,
    watchtower_idx: OperatorIdx,
) -> Result<XOnlyPublicKey, ExecutorError> {
    let path = root()?
        .join("setup")
        .join(setup_name(graph_idx, game_index, watchtower_idx));
    let bytes = read_required(path, "RankLock setup commitment")?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|err| {
        ExecutorError::RanklockErr(format!(
            "RankLock setup commitment is not a valid compatibility x-only value: {err}"
        ))
    })
}

/// Loads and verifies the concrete positive-lock ACK preimage.
///
/// A missing file is not an error: it means the positive predicate has not
/// released an unlock, so callers retry while the fixed timeout NACK remains
/// the default branch. Malformed or hash-mismatched files are hard failures and
/// are never broadcast.
pub(super) fn load_ack_preimage(
    bridge_proof_txid: Txid,
    counterproof_txid: Txid,
    counterproof_ack_txid: Txid,
    expected_hash: [u8; 32],
) -> Result<Option<[u8; 32]>, ExecutorError> {
    let path = root()?
        .join("unlock")
        .join(unlock_name(
            bridge_proof_txid,
            counterproof_txid,
            counterproof_ack_txid,
        ));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ExecutorError::RanklockErr(format!(
                "failed to read RankLock ACK preimage at {}: {err}",
                path.display()
            )))
        }
    };
    let preimage = decode_32(&bytes, "RankLock ACK preimage")?;
    let actual_hash = sha256::Hash::hash(&preimage).to_byte_array();
    if actual_hash != expected_hash {
        return Err(ExecutorError::RanklockErr(format!(
            "RankLock ACK preimage hash mismatch for ack tx {counterproof_ack_txid}"
        )));
    }
    Ok(Some(preimage))
}

/// Resolves the positive lock and publishes the exact pre-signed ACK when an
/// unlock is available. A missing unlock is a successful no-op; retry/new-block
/// handling will revisit it while the timeout NACK races independently.
pub(super) async fn resolve_and_publish_counterproof_ack(
    output_handles: &OutputHandles,
    bridge_proof_txid: Txid,
    counterproof_txid: Txid,
    counterproof_ack_tx: CounterproofAckTx,
    n_of_n_signatures: [Signature; CounterproofAckTx::N_INPUTS],
) -> Result<(), ExecutorError> {
    let counterproof_ack_txid = counterproof_ack_tx.as_ref().compute_txid();
    let expected_hash = counterproof_ack_tx.ack_preimage_hash();
    let Some(preimage) = load_ack_preimage(
        bridge_proof_txid,
        counterproof_txid,
        counterproof_ack_txid,
        expected_hash,
    )? else {
        info!(
            %bridge_proof_txid,
            %counterproof_txid,
            %counterproof_ack_txid,
            "RankLock ACK unlock is not available yet"
        );
        return Ok(());
    };

    if !counterproof_ack_tx.accepts_preimage(&preimage) {
        warn!(%counterproof_ack_txid, "verified RankLock preimage was rejected by connector");
        return Err(ExecutorError::RanklockErr(
            "connector rejected a hash-verified ACK preimage".into(),
        ));
    }

    let signed = counterproof_ack_tx.finalize(preimage, n_of_n_signatures);
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed,
        "validity-first counterproof ack",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the fixed pre-signed timeout NACK.
pub(super) async fn publish_timeout_nack(
    output_handles: &OutputHandles,
    signed_nack: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_nack,
        "validity-first counterproof timeout nack",
        TxStatus::is_buried,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_raw_and_hex() {
        let bytes = [0xAB; 32];
        assert_eq!(decode_32(&bytes, "test").unwrap(), bytes);
        let hex = "ab".repeat(32);
        assert_eq!(decode_32(hex.as_bytes(), "test").unwrap(), bytes);
    }

    #[test]
    fn rejects_malformed_values() {
        assert!(decode_32(&[0u8; 31], "test").is_err());
        assert!(decode_32(b"not-hex", "test").is_err());
        assert!(decode_32(&[b'z'; 64], "test").is_err());
    }

    #[test]
    fn setup_and_unlock_names_bind_full_context() {
        use strata_bridge_primitives::types::{DepositIdx, GraphIdx};

        let a = GraphIdx { operator: 2, deposit: DepositIdx::from(7u32) };
        let b = GraphIdx { operator: 2, deposit: DepositIdx::from(8u32) };
        let game = GameIndex::try_from(7u32).unwrap();
        assert_ne!(setup_name(a, game, 3), setup_name(b, game, 3));
        assert_ne!(
            unlock_name(Txid::all_zeros(), Txid::all_zeros(), Txid::all_zeros()),
            unlock_name(Txid::all_zeros(), Txid::all_zeros(), Txid::from_byte_array([1u8; 32])),
        );
    }
}
