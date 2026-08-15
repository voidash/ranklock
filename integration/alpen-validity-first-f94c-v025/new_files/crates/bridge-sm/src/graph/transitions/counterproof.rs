use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{Transaction, Txid};
use strata_bridge_tx_graph::game_graph::{DepositParams, GameGraphSummary};
use strata_mosaic_client_api::types::{
    CompletedSignatures, N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES, Signature,
};

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::CounterProofConfirmedEvent,
    machine::{GSMOutput, GraphSM},
    state::{CounterproofData, GraphState},
    watchtower::watchtower_slot_for_operator,
};

impl GraphSM {
    /// Processes a confirmed counterproof. The transaction and witness are validated and
    /// retained exactly as before. Polarity is inverted: the counterproving watchtower may
    /// resolve an immediate ACK when the RankLock unlock exists; the graph owner does not
    /// publish a NACK here because the fixed NACK is CSV-delayed.
    pub(crate) fn process_counterproof(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        event: CounterProofConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        self.check_operator_idx(event.counterprover_idx, &event)?;

        match self.state.clone() {
            GraphState::Contested {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                let (ack_duties, completed_signatures) = self
                    .validate_counterproof_and_resolve_ack(
                        &cfg,
                        &event,
                        &graph_data,
                        &graph_summary,
                        &signatures,
                        None,
                    )?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof: None,
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(ack_duties))
            }
            GraphState::BridgeProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                proof,
                bridge_proof_tx,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                let (ack_duties, completed_signatures) = self
                    .validate_counterproof_and_resolve_ack(
                        &cfg,
                        &event,
                        &graph_data,
                        &graph_summary,
                        &signatures,
                        Some(bridge_proof_tx.compute_txid()),
                    )?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof: Some((bridge_proof_tx, proof)),
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(ack_duties))
            }
            GraphState::CounterProofPosted {
                mut counterproofs_and_confs,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_bridge_proof,
                counterproof_nacks,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                if counterproofs_and_confs.contains_key(&event.counterprover_idx) {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }

                let bridge_proof_txid = refuted_bridge_proof
                    .as_ref()
                    .map(|(tx, _)| tx.compute_txid());
                let (ack_duties, completed_signatures) = self
                    .validate_counterproof_and_resolve_ack(
                        &cfg,
                        &event,
                        &graph_data,
                        &graph_summary,
                        &signatures,
                        bridge_proof_txid,
                    )?;

                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof,
                    counterproofs_and_confs,
                    counterproof_nacks,
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(ack_duties))
            }
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }

    fn validate_counterproof_and_resolve_ack(
        &self,
        cfg: &GraphSMCfg,
        event: &CounterProofConfirmedEvent,
        graph_data: &DepositParams,
        graph_summary: &GameGraphSummary,
        signatures: &[Signature],
        bridge_proof_txid: Option<Txid>,
    ) -> GSMResult<(Vec<GraphDuty>, CompletedSignatures)> {
        let counterproof_txid = event.tx.compute_txid();

        let graph_owner_idx = self.context().operator_idx();
        let watchtower_slot =
            watchtower_slot_for_operator(graph_owner_idx, event.counterprover_idx).ok_or_else(
                || {
                    GSMError::rejected(
                        self.state.clone(),
                        event.clone().into(),
                        format!(
                            "operator {} has no counterproof slot in graph owned by {}",
                            event.counterprover_idx, graph_owner_idx,
                        ),
                    )
                },
            )?;
        let expected_counterproof_txid = graph_summary
            .counterproofs
            .get(watchtower_slot)
            .map(|summary| summary.counterproof)
            .ok_or_else(|| {
                GSMError::rejected(
                    self.state.clone(),
                    event.clone().into(),
                    format!("missing counterproof summary for watchtower slot {watchtower_slot}"),
                )
            })?;
        if counterproof_txid != expected_counterproof_txid {
            return Err(GSMError::rejected(
                self.state.clone(),
                event.clone().into(),
                "counterproof txid does not match the claimed counterprover slot",
            ));
        }

        let completed_signatures = self.decode_completed_sigs(&event.tx, event)?;
        let duties = if self.context().operator_table().pov_idx() == event.counterprover_idx {
            bridge_proof_txid
                .map(|txid| {
                    self.validity_first_ack_duty(
                        cfg,
                        graph_data,
                        signatures,
                        txid,
                        event.counterprover_idx,
                        event.clone().into(),
                    )
                })
                .transpose()?
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };

        Ok((duties, completed_signatures))
    }

    /// Decodes the per-byte operator signatures from an on-chain Counterproof tx, in byte order.
    fn decode_completed_sigs(
        &self,
        counterproof_tx: &Transaction,
        event: &CounterProofConfirmedEvent,
    ) -> GSMResult<CompletedSignatures> {
        const N: usize = N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES;
        const WANT: usize = N + 3;

        let witness_len = counterproof_tx.input[0].witness.len();
        if witness_len != WANT {
            return Err(GSMError::rejected(
                self.state.clone(),
                event.clone().into(),
                format!("counterproof witness has {witness_len} elements, expected {WANT}"),
            ));
        }

        let mut items = counterproof_tx.input[0].witness.to_vec();
        items.reverse();
        let sigs: Vec<Signature> = items
            .into_iter()
            .skip(3)
            .enumerate()
            .map(|(idx, w)| {
                Signature::from_slice(&w).map_err(|_| {
                    GSMError::rejected(
                        self.state.clone(),
                        event.clone().into(),
                        format!("counterproof witness signature {idx} is malformed"),
                    )
                })
            })
            .collect::<GSMResult<Vec<_>>>()?;

        sigs.try_into().map_err(|_| {
            GSMError::rejected(
                self.state.clone(),
                event.clone().into(),
                "counterproof witness has an invalid signature count",
            )
        })
    }
}
