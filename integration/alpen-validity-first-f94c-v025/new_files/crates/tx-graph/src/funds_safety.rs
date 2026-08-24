//! Read-only economic safety analysis for validity-first graph candidates.
//!
//! This module is a kill witness, not an authorization mechanism.  It reports
//! a concrete graph trace that violates the valid-counterproof terminal
//! allowlist when one participant shared by every ACK release withholds.

use std::{collections::BTreeSet, error::Error, fmt};

use bitcoin::{
    hashes::{sha256, Hash},
    Amount, OutPoint, ScriptBuf, Txid,
};
use serde::{Deserialize, Serialize};

use crate::{
    game_graph::GameGraph,
    transactions::prelude::{CounterproofAckTx, CounterproofTx},
};

/// Schema emitted by [`detect_correlated_ack_withholder_loss`].
pub const ECONOMIC_KILL_WITNESS_SCHEMA: &str = "strata-validity-first-economic-kill-witness-v1";

/// RankLock release threshold shared by every ACK path in one graph.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AckReleasePolicy {
    total_participants: u16,
    required_participants: u16,
}

impl AckReleasePolicy {
    /// Constructs a bounded release policy.
    ///
    /// RankLock's selected split-scalar profile admits 2 through 64 ordered
    /// participants.  A threshold outside `1..=total_participants` is invalid.
    pub fn new(
        total_participants: u16,
        required_participants: u16,
    ) -> Result<Self, EconomicSafetyError> {
        if !(2..=64).contains(&total_participants) {
            return Err(EconomicSafetyError::InvalidReleasePolicy(
                "total participants must be in 2..=64",
            ));
        }
        if required_participants == 0 || required_participants > total_participants {
            return Err(EconomicSafetyError::InvalidReleasePolicy(
                "required participants must be in 1..=total participants",
            ));
        }
        Ok(Self {
            total_participants,
            required_participants,
        })
    }

    /// Returns the total number of enrolled release participants.
    pub const fn total_participants(self) -> u16 {
        self.total_participants
    }

    /// Returns the number of releases required to reconstruct an ACK secret.
    pub const fn required_participants(self) -> u16 {
        self.required_participants
    }

    /// Whether one withholding participant blocks every ACK release.
    pub const fn one_withholder_blocks(self) -> bool {
        self.required_participants == self.total_participants
    }
}

/// Exact premise under which the witness is evaluated.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicSafetyPremise {
    /// A counterproof is valid and one participant required by every ACK withholds.
    VerifiedValidCounterproofWithOneRequiredReleaseWithholder,
}

/// Reason the applied graph fails the valid-counterproof terminal allowlist.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicKillReason {
    /// Timeout reaches owner payout while the canonical ACK reaches slash.
    ValidCounterproofCanReachOwnerContestedPayoutAndAvoidCanonicalSlash,
}

/// Typed, non-authorizing counterexample extracted from exact graph templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicKillWitness {
    /// Versioned report schema.
    pub schema: String,
    /// Evaluated adversarial premise.
    pub premise: EconomicSafetyPremise,
    /// Why the trace violates the valid-counterproof terminal allowlist.
    pub reason: EconomicKillReason,
    /// This field is always false for a returned kill witness.
    pub funds_safe_under_premise: bool,
    /// Selected ACK slot used for the canonical valid-counterproof baseline.
    pub selected_ack_slot: u32,
    /// Total release participants shared by every ACK path.
    pub release_total_participants: u16,
    /// Required release participants shared by every ACK path.
    pub release_required_participants: u16,
    /// Exact ordered connector outpoints on which each ACK and NACK conflict.
    pub ordered_ack_nack_outpoints: Vec<OutPoint>,
    /// Exact canonical selected ACK transaction id.
    pub canonical_ack_txid: Txid,
    /// Value assigned to the selected watchtower's ACK anchor.
    pub canonical_ack_watchtower_output_sat: u64,
    /// Exact canonical slash transaction id.
    pub canonical_slash_txid: Txid,
    /// Total slash value assigned to the ordered watchtower set.
    pub canonical_slash_watchtower_outputs_sat: u64,
    /// Exact ordered timeout NACK transaction ids.
    pub withholding_nack_txids: Vec<Txid>,
    /// Total NACK-anchor value assigned to the graph owner.
    pub withholding_nack_owner_outputs_sat: u64,
    /// Exact contested-payout transaction id.
    pub withholding_contested_payout_txid: Txid,
    /// Contested-payout value assigned to the graph owner.
    pub withholding_contested_payout_owner_output_sat: u64,
    /// Owner-controlled value emitted by the demonstrated timeout branch.
    pub withholding_owner_receipts_sat: u64,
    /// Watchtower-controlled value emitted by the canonical ACK/slash branch.
    pub canonical_protected_receipts_sat: u64,
    /// Contest-payout outpoint consumed by ACK but by contested payout on timeout.
    pub shared_ack_contested_payout_outpoint: OutPoint,
    /// Contest-slash outpoint consumed by slash but by contested payout on timeout.
    pub shared_slash_contested_payout_outpoint: OutPoint,
    /// Stake outpoint consumed by canonical slash and not by contested payout.
    pub residual_stake_outpoint: OutPoint,
    /// False because this graph contains no signed post-NACK stake disposition theorem.
    pub residual_stake_disposition_proven: bool,
}

/// Fail-closed errors returned while extracting graph economics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicSafetyError {
    /// Release threshold is outside the selected profile's bounds.
    InvalidReleasePolicy(&'static str),
    /// Graph has no counterproof slot.
    EmptyCounterproofSet,
    /// Ordered watchtower principals do not match counterproof slots.
    WatchtowerCountMismatch {
        /// Transaction branch whose beneficiary roster is malformed.
        branch: &'static str,
        /// Number of watchtower principals required by the graph.
        expected: usize,
        /// Number of watchtower principals supplied by the signed policy.
        actual: usize,
    },
    /// Graph owner and watchtower scripts overlap or a watchtower script repeats.
    AmbiguousBeneficiaryScript,
    /// Selected ACK slot is outside the graph.
    InvalidSelectedAckSlot(u32),
    /// An ACK or NACK does not have the required fixed shape.
    MalformedAckNackSlot {
        /// Ordered counterproof slot containing the malformed transaction.
        slot: u32,
        /// Exact invariant that the transaction violates.
        detail: &'static str,
    },
    /// ACK and NACK do not conflict on the exact counterproof outpoint.
    AckNackOutpointMismatch {
        /// Ordered counterproof slot containing the conflict mismatch.
        slot: u32,
    },
    /// A graph output does not pay its committed economic principal.
    UnexpectedBeneficiary {
        /// Transaction branch containing the unexpected script.
        branch: &'static str,
        /// Output or participant index containing the unexpected script.
        index: usize,
    },
    /// Contested payout does not have the reviewed four-input/one-output shape.
    MalformedContestedPayout,
    /// Slash does not have the reviewed two-input/header-plus-watchtowers shape.
    MalformedSlash,
    /// ACK, slash, and contested payout do not conflict on reviewed outpoints.
    TerminalConflictMismatch(&'static str),
    /// A value sum overflowed.
    ValueOverflow(&'static str),
}

impl fmt::Display for EconomicSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReleasePolicy(detail) => {
                write!(formatter, "invalid ACK release policy: {detail}")
            }
            Self::EmptyCounterproofSet => write!(formatter, "graph has no counterproof slots"),
            Self::WatchtowerCountMismatch {
                branch,
                expected,
                actual,
            } => write!(
                formatter,
                "{branch} watchtower script count mismatch: expected {expected}, found {actual}"
            ),
            Self::AmbiguousBeneficiaryScript => {
                write!(formatter, "economic beneficiary scripts are ambiguous")
            }
            Self::InvalidSelectedAckSlot(slot) => {
                write!(formatter, "selected ACK slot {slot} is outside the graph")
            }
            Self::MalformedAckNackSlot { slot, detail } => {
                write!(formatter, "malformed ACK/NACK slot {slot}: {detail}")
            }
            Self::AckNackOutpointMismatch { slot } => {
                write!(
                    formatter,
                    "ACK/NACK slot {slot} does not share one outpoint"
                )
            }
            Self::UnexpectedBeneficiary { branch, index } => write!(
                formatter,
                "{branch} output {index} does not pay the committed beneficiary"
            ),
            Self::MalformedContestedPayout => {
                write!(
                    formatter,
                    "contested payout has an unexpected transaction shape"
                )
            }
            Self::MalformedSlash => {
                write!(formatter, "slash has an unexpected transaction shape")
            }
            Self::TerminalConflictMismatch(detail) => {
                write!(formatter, "terminal graph conflict mismatch: {detail}")
            }
            Self::ValueOverflow(label) => write!(formatter, "{label} value sum overflowed"),
        }
    }
}

impl Error for EconomicSafetyError {}

/// Detects the current graph's valid-counterproof/one-withholder loss trace.
///
/// `Ok(None)` means only that this one correlated-withholder counterexample was
/// not reproduced for the supplied threshold.  It is not a funds-safety proof.
/// The function never participates in admission or transaction authorization.
pub fn detect_correlated_ack_withholder_loss(
    graph: &GameGraph,
    graph_owner_script: &ScriptBuf,
    ordered_ack_anchor_scripts: &[ScriptBuf],
    ordered_slash_beneficiary_scripts: &[ScriptBuf],
    selected_ack_slot: u32,
    release_policy: AckReleasePolicy,
) -> Result<Option<EconomicKillWitness>, EconomicSafetyError> {
    if graph.counterproofs.is_empty() {
        return Err(EconomicSafetyError::EmptyCounterproofSet);
    }
    if graph.counterproofs.len() != ordered_ack_anchor_scripts.len() {
        return Err(EconomicSafetyError::WatchtowerCountMismatch {
            branch: "ACK-anchor",
            expected: graph.counterproofs.len(),
            actual: ordered_ack_anchor_scripts.len(),
        });
    }
    if graph.counterproofs.len() != ordered_slash_beneficiary_scripts.len() {
        return Err(EconomicSafetyError::WatchtowerCountMismatch {
            branch: "slash",
            expected: graph.counterproofs.len(),
            actual: ordered_slash_beneficiary_scripts.len(),
        });
    }
    validate_beneficiary_scripts(graph_owner_script, ordered_ack_anchor_scripts)?;
    validate_beneficiary_scripts(graph_owner_script, ordered_slash_beneficiary_scripts)?;

    let selected_slot = usize::try_from(selected_ack_slot)
        .ok()
        .filter(|slot| *slot < graph.counterproofs.len())
        .ok_or(EconomicSafetyError::InvalidSelectedAckSlot(
            selected_ack_slot,
        ))?;

    let mut ordered_ack_nack_outpoints = Vec::with_capacity(graph.counterproofs.len());
    let mut withholding_nack_txids = Vec::with_capacity(graph.counterproofs.len());
    let mut withholding_nack_owner_outputs_sat = 0u64;
    let mut canonical_ack_txid = None;
    let mut canonical_ack_watchtower_output_sat = None;

    for (slot, counterproof) in graph.counterproofs.iter().enumerate() {
        let slot_u32 =
            u32::try_from(slot).map_err(|_| EconomicSafetyError::MalformedAckNackSlot {
                slot: u32::MAX,
                detail: "slot index exceeds u32",
            })?;
        let ack = counterproof.counterproof_ack.as_ref();
        let nack = counterproof.counterproof_nack.as_ref();
        if ack.input.len() != CounterproofAckTx::N_INPUTS || ack.output.len() != 1 {
            return Err(EconomicSafetyError::MalformedAckNackSlot {
                slot: slot_u32,
                detail: "ACK must have two inputs and one output",
            });
        }
        if nack.input.len() != 1 || nack.output.len() != 1 {
            return Err(EconomicSafetyError::MalformedAckNackSlot {
                slot: slot_u32,
                detail: "NACK must have one input and one output",
            });
        }

        let expected_outpoint = OutPoint {
            txid: counterproof.counterproof.as_ref().compute_txid(),
            vout: CounterproofTx::ACK_NACK_VOUT,
        };
        if ack.input[0].previous_output != expected_outpoint
            || nack.input[0].previous_output != expected_outpoint
        {
            return Err(EconomicSafetyError::AckNackOutpointMismatch { slot: slot_u32 });
        }
        if nack.output[0].script_pubkey != *graph_owner_script {
            return Err(EconomicSafetyError::UnexpectedBeneficiary {
                branch: "timeout_nack",
                index: slot,
            });
        }
        if ack.output[0].script_pubkey != ordered_ack_anchor_scripts[slot] {
            return Err(EconomicSafetyError::UnexpectedBeneficiary {
                branch: "canonical_ack",
                index: slot,
            });
        }
        if nack.output[0].value == Amount::ZERO || ack.output[0].value == Amount::ZERO {
            return Err(EconomicSafetyError::MalformedAckNackSlot {
                slot: slot_u32,
                detail: "ACK/NACK outputs must be positive",
            });
        }

        ordered_ack_nack_outpoints.push(expected_outpoint);
        withholding_nack_txids.push(nack.compute_txid());
        withholding_nack_owner_outputs_sat = withholding_nack_owner_outputs_sat
            .checked_add(nack.output[0].value.to_sat())
            .ok_or(EconomicSafetyError::ValueOverflow("timeout NACK"))?;
        if slot == selected_slot {
            canonical_ack_txid = Some(ack.compute_txid());
            canonical_ack_watchtower_output_sat = Some(ack.output[0].value.to_sat());
        }
    }

    let contested_payout = graph.contested_payout.as_ref();
    if contested_payout.input.len() != 4 || contested_payout.output.len() != 1 {
        return Err(EconomicSafetyError::MalformedContestedPayout);
    }
    if contested_payout.output[0].script_pubkey != *graph_owner_script
        || contested_payout.output[0].value == Amount::ZERO
    {
        return Err(EconomicSafetyError::UnexpectedBeneficiary {
            branch: "contested_payout",
            index: 0,
        });
    }

    let slash = graph.slash.as_ref();
    if slash.input.len() != 2 || slash.output.len() != ordered_slash_beneficiary_scripts.len() + 1 {
        return Err(EconomicSafetyError::MalformedSlash);
    }
    if slash.output[0].value != Amount::ZERO || !slash.output[0].script_pubkey.is_op_return() {
        return Err(EconomicSafetyError::MalformedSlash);
    }
    let mut canonical_slash_watchtower_outputs_sat = 0u64;
    for (index, (output, expected_script)) in slash
        .output
        .iter()
        .skip(1)
        .zip(ordered_slash_beneficiary_scripts)
        .enumerate()
    {
        if output.script_pubkey != *expected_script || output.value == Amount::ZERO {
            return Err(EconomicSafetyError::UnexpectedBeneficiary {
                branch: "canonical_slash",
                index,
            });
        }
        canonical_slash_watchtower_outputs_sat = canonical_slash_watchtower_outputs_sat
            .checked_add(output.value.to_sat())
            .ok_or(EconomicSafetyError::ValueOverflow("canonical slash"))?;
    }

    let selected_ack = graph.counterproofs[selected_slot].counterproof_ack.as_ref();
    let shared_ack_contested_payout_outpoint = selected_ack.input[1].previous_output;
    if contested_payout.input[2].previous_output != shared_ack_contested_payout_outpoint {
        return Err(EconomicSafetyError::TerminalConflictMismatch(
            "ACK and contested payout do not share the contest-payout outpoint",
        ));
    }
    let shared_slash_contested_payout_outpoint = slash.input[0].previous_output;
    if contested_payout.input[3].previous_output != shared_slash_contested_payout_outpoint {
        return Err(EconomicSafetyError::TerminalConflictMismatch(
            "slash and contested payout do not share the contest-slash outpoint",
        ));
    }
    let residual_stake_outpoint = slash.input[1].previous_output;

    if !release_policy.one_withholder_blocks() {
        return Ok(None);
    }

    let canonical_ack_watchtower_output_sat = canonical_ack_watchtower_output_sat.ok_or(
        EconomicSafetyError::InvalidSelectedAckSlot(selected_ack_slot),
    )?;
    let canonical_ack_txid = canonical_ack_txid.ok_or(
        EconomicSafetyError::InvalidSelectedAckSlot(selected_ack_slot),
    )?;
    let withholding_contested_payout_owner_output_sat = contested_payout.output[0].value.to_sat();
    let withholding_owner_receipts_sat = withholding_nack_owner_outputs_sat
        .checked_add(withholding_contested_payout_owner_output_sat)
        .ok_or(EconomicSafetyError::ValueOverflow(
            "withholding owner receipts",
        ))?;
    let canonical_protected_receipts_sat = canonical_ack_watchtower_output_sat
        .checked_add(canonical_slash_watchtower_outputs_sat)
        .ok_or(EconomicSafetyError::ValueOverflow(
            "canonical protected receipts",
        ))?;

    Ok(Some(EconomicKillWitness {
        schema: ECONOMIC_KILL_WITNESS_SCHEMA.to_owned(),
        premise: EconomicSafetyPremise::VerifiedValidCounterproofWithOneRequiredReleaseWithholder,
        reason:
            EconomicKillReason::ValidCounterproofCanReachOwnerContestedPayoutAndAvoidCanonicalSlash,
        funds_safe_under_premise: false,
        selected_ack_slot,
        release_total_participants: release_policy.total_participants(),
        release_required_participants: release_policy.required_participants(),
        ordered_ack_nack_outpoints,
        canonical_ack_txid,
        canonical_ack_watchtower_output_sat,
        canonical_slash_txid: slash.compute_txid(),
        canonical_slash_watchtower_outputs_sat,
        withholding_nack_txids,
        withholding_nack_owner_outputs_sat,
        withholding_contested_payout_txid: contested_payout.compute_txid(),
        withholding_contested_payout_owner_output_sat,
        withholding_owner_receipts_sat,
        canonical_protected_receipts_sat,
        shared_ack_contested_payout_outpoint,
        shared_slash_contested_payout_outpoint,
        residual_stake_outpoint,
        residual_stake_disposition_proven: false,
    }))
}

fn validate_beneficiary_scripts(
    graph_owner_script: &ScriptBuf,
    ordered_watchtower_scripts: &[ScriptBuf],
) -> Result<(), EconomicSafetyError> {
    let owner_digest = script_digest(graph_owner_script);
    let mut watchtower_digests = BTreeSet::new();
    for script in ordered_watchtower_scripts {
        let digest = script_digest(script);
        if digest == owner_digest || !watchtower_digests.insert(digest) {
            return Err(EconomicSafetyError::AmbiguousBeneficiaryScript);
        }
    }
    Ok(())
}

fn script_digest(script: &ScriptBuf) -> [u8; 32] {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_policy_bounds_are_strict() {
        assert!(matches!(
            AckReleasePolicy::new(1, 1),
            Err(EconomicSafetyError::InvalidReleasePolicy(_))
        ));
        assert!(matches!(
            AckReleasePolicy::new(65, 65),
            Err(EconomicSafetyError::InvalidReleasePolicy(_))
        ));
        assert!(matches!(
            AckReleasePolicy::new(2, 0),
            Err(EconomicSafetyError::InvalidReleasePolicy(_))
        ));
        assert!(matches!(
            AckReleasePolicy::new(2, 3),
            Err(EconomicSafetyError::InvalidReleasePolicy(_))
        ));
        assert!(AckReleasePolicy::new(2, 2)
            .expect("2-of-2 is valid")
            .one_withholder_blocks());
        assert!(!AckReleasePolicy::new(2, 1)
            .expect("1-of-2 is valid")
            .one_withholder_blocks());
    }
}
