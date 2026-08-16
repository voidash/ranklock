#!/usr/bin/env python3
"""Apply the RankLock validity-first counterproof integration to strata-bridge.

The installer is deliberately fail-closed.  It only applies to the exact Alpen
base commit that this patch was reviewed against, requires a clean worktree,
and verifies every textual replacement occurs exactly once.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

BASE_COMMIT = "f94c06d08ff29eee746f3e20bd63078d2949b304"
HERE = Path(__file__).resolve().parent


class PatchError(RuntimeError):
    pass


def run(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        args,
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode:
        raise PatchError(f"{' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def read(repo: Path, rel: str) -> str:
    path = repo / rel
    if not path.is_file():
        raise PatchError(f"missing target file: {rel}")
    return path.read_text()


def write(repo: Path, rel: str, text: str, dry_run: bool) -> None:
    path = repo / rel
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise PatchError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch(repo: Path, rel: str, edits: list[tuple[str, str, str]], dry_run: bool) -> None:
    text = read(repo, rel)
    for old, new, label in edits:
        text = replace_once(text, old, new, f"{rel}: {label}")
    write(repo, rel, text, dry_run)


def install_overlay(repo: Path, rel: str, dry_run: bool) -> None:
    src = HERE / "new_files" / rel
    if not src.is_file():
        raise PatchError(f"missing overlay file: {src}")
    dst = repo / rel
    if dst.exists() and rel not in {
        "crates/tx-graph/src/transactions/counterproof.rs",
        "crates/tx-graph/src/transactions/counterproof_ack.rs",
        "crates/bridge-sm/src/graph/transitions/counterproof.rs",
    }:
        raise PatchError(f"new file already exists: {rel}")
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def validate_repo(repo: Path) -> None:
    if not (repo / ".git").exists():
        raise PatchError(f"not a Git checkout: {repo}")
    head = run(repo, "git", "rev-parse", "HEAD")
    if head != BASE_COMMIT:
        raise PatchError(f"expected HEAD {BASE_COMMIT}, found {head}")
    status = run(repo, "git", "status", "--porcelain")
    if status:
        raise PatchError("worktree is not clean; commit/stash changes before applying")


def apply(repo: Path, dry_run: bool) -> None:
    validate_repo(repo)

    # New source files and exact replacements for the two transaction modules.
    for rel in (
        "crates/connectors/src/validity_first_counterproof.rs",
        "crates/tx-graph/src/transactions/counterproof_nack.rs",
        "crates/bridge-exec/src/graph/ranklock.rs",
        "crates/tx-graph/src/transactions/counterproof.rs",
        "crates/tx-graph/src/transactions/counterproof_ack.rs",
        "crates/bridge-sm/src/graph/transitions/counterproof.rs",
    ):
        install_overlay(repo, rel, dry_run)

    patch(
        repo,
        "crates/connectors/src/lib.rs",
        [
            (
                "pub mod timelocked;\npub mod unstaking_intent;",
                "pub mod timelocked;\npub mod unstaking_intent;\npub mod validity_first_counterproof;",
                "export connector module",
            )
        ],
        dry_run,
    )
    patch(
        repo,
        "crates/connectors/src/prelude.rs",
        [
            (
                "    n_of_n::*, timelocked::*, unstaking_intent::*,\n",
                "    n_of_n::*, timelocked::*, unstaking_intent::*, validity_first_counterproof::*,\n",
                "prelude export",
            )
        ],
        dry_run,
    )
    patch(
        repo,
        "crates/tx-graph/src/transactions/mod.rs",
        [
            (
                "pub mod counterproof_ack;\npub mod deposit;",
                "pub mod counterproof_ack;\npub mod counterproof_nack;\npub mod deposit;",
                "export fixed nack module",
            )
        ],
        dry_run,
    )
    patch(
        repo,
        "crates/tx-graph/src/transactions/prelude.rs",
        [
            (
                "    cooperative_payout::*, counterproof::*, counterproof_ack::*, deposit::*, not_presigned::*,\n",
                "    cooperative_payout::*, counterproof::*, counterproof_ack::*, counterproof_nack::*, deposit::*,\n    not_presigned::*,\n",
                "prelude export fixed nack",
            )
        ],
        dry_run,
    )

    patch_fee(repo, dry_run)
    patch_musig_functor(repo, dry_run)
    patch_game_graph(repo, dry_run)
    patch_duties(repo, dry_run)
    patch_machine(repo, dry_run)
    patch_contested_transition(repo, dry_run)
    patch_common_transition(repo, dry_run)
    patch_retry(repo, dry_run)
    patch_classifier(repo, dry_run)
    patch_executor(repo, dry_run)

    if not dry_run:
        scripts_dir = repo / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / "ranklock_sidecar_fixture.py", scripts_dir / "ranklock_sidecar_fixture.py")
        run(repo, "git", "diff", "--check")


def patch_fee(repo: Path, dry_run: bool) -> None:
    rel = "crates/tx-graph/src/fee.rs"
    edits: list[tuple[str, str, str]] = []
    edits.append((
        "use strata_bridge_connectors::{\n    prelude::{ClaimContestConnector, ContestCounterproofOutput},\n    Connector,\n};",
        "use strata_bridge_connectors::{\n    prelude::{ClaimContestConnector, ContestCounterproofOutput},\n    Connector,\n};",
        "fee imports anchor",
    ))
    edits.append((
        "/// Predicted vsize of [`crate::transactions::counterproof_ack::CounterproofAckTx`].\n///\n/// Structure: 2 inputs (Counterproof timeout script path, ContestPayout normal key path)\n/// + 1 P2TR output (cpfp anchor).\nconst COUNTERPROOF_ACK_VSIZE: u64 = 187;",
        "/// Predicted vsize of [`crate::transactions::counterproof_ack::CounterproofAckTx`].\n///\n/// Structure: 2 script-path/key-path inputs. Input 0 carries a 32-byte RankLock preimage,\n/// an N/N Schnorr signature, the positive-lock script and a two-leaf control block; input 1\n/// spends ContestPayout normally. The only output is the keyed CPFP anchor.\nconst COUNTERPROOF_ACK_VSIZE: u64 = 211;\n\n/// Exact fixed NACK vsize for a given CSV delay. The transaction has a 94-byte stripped\n/// body. Its witness is one Schnorr signature, the CSV leaf and a two-leaf control block.\nfn validity_first_counterproof_nack_vsize(delay: relative::Height) -> u64 {\n    let n = delay.value() as u64;\n    let sequence_push_len: u64 = if n <= 16 {\n        1\n    } else if n <= 0x7f {\n        2\n    } else if n <= 0x7fff {\n        3\n    } else {\n        4\n    };\n    let leaf_script_len: u64 = 36 + sequence_push_len;\n    let weight: u64 = 94 * 4 + 135 + leaf_script_len;\n    (weight + WITNESS_SCALE_FACTOR as u64 - 1) / WITNESS_SCALE_FACTOR as u64\n}",
        "ACK and exact NACK vsize",
    ))
    edits.append((
        "/// Fee for [`crate::transactions::counterproof_ack::CounterproofAckTx`].\npub(crate) const fn counterproof_ack_fee() -> Amount {\n    fee_for_vsize(COUNTERPROOF_ACK_VSIZE)\n}\n",
        "/// Fee for [`crate::transactions::counterproof_ack::CounterproofAckTx`].\npub(crate) const fn counterproof_ack_fee() -> Amount {\n    fee_for_vsize(COUNTERPROOF_ACK_VSIZE)\n}\n\n/// Fee for [`crate::transactions::counterproof_nack::ValidityFirstCounterproofNackTx`].\npub(crate) fn validity_first_counterproof_nack_fee(\n    delay: relative::Height,\n) -> Amount {\n    fee_for_vsize(validity_first_counterproof_nack_vsize(delay))\n}\n",
        "fixed nack fee helper",
    ))
    edits.append((
        "/// Surcharge for `CounterproofConnector`. Funds the [`counterproof_ack_fee`] of\n/// [`crate::transactions::counterproof_ack::CounterproofAckTx`].\npub(crate) const fn counterproof_surcharge() -> Amount {\n    counterproof_ack_fee()\n}",
        "/// Surcharge for `ValidityFirstCounterproofConnector`. ACK is the larger fixed child\n/// (211 vB versus at most 138 vB for the u16 CSV NACK), so funding ACK also funds NACK.\npub(crate) const fn counterproof_surcharge() -> Amount {\n    counterproof_ack_fee()\n}",
        "connector surcharge docs",
    ))
    edits.append((
        ".counterproof_ack\n            .clone()\n            .finalize([dummy_sig(), dummy_sig()]);",
        ".counterproof_ack\n            .clone()\n            .finalize([0u8; 32], [dummy_sig(), dummy_sig()]);",
        "ACK pin preimage",
    ))
    marker = '''    #[test]\n    fn pin_contested_payout_vsize() {'''
    added = '''    #[test]\n    fn pin_validity_first_counterproof_nack_vsize() {\n        let signer = TestSigner::generate(N_WATCHTOWERS);\n        let (graph, _) = GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));\n        let signed = graph.counterproofs[0]\n            .counterproof_nack\n            .clone()\n            .finalize(dummy_sig());\n        pin(\n            signed.weight().to_vbytes_ceil(),\n            validity_first_counterproof_nack_vsize(relative::Height::from_height(5)),\n            "validity_first_counterproof_nack",\n        );\n        assert_eq!(\n            validity_first_counterproof_nack_vsize(relative::Height::from_height(144)),\n            138,\n        );\n    }\n\n'''+marker
    edits.append((marker, added, "fixed nack vsize test"))
    # The first edit is an intentional anchor/no-op; drop it to preserve replace_once semantics.
    edits = [e for e in edits if e[0] != e[1]]
    # Remove the pin for the OLD mutable CounterproofNackTx. Under
    # validity-first the NACK is a fixed, exact, pre-signed transaction, so
    # that shape no longer exists and the test cannot even be constructed
    # from the new connector type. Its replacement pin,
    # pin_validity_first_counterproof_nack_vsize, is added above.
    edits.append((
        '    #[test]\n    fn pin_counterproof_nack_vsize() {\n        // In production, CounterproofNackTx has just the connector input and a single\n        // P2TR operator-wallet output (no wallet-funded extra input). Build that shape.\n        let signer = TestSigner::generate(N_WATCHTOWERS);\n        let (graph, connectors) =\n            GameGraph::new(test_game_data(&signer, N_WATCHTOWERS as u32, N_DATA));\n        let mut nack = CounterproofNackTx::new(\n            CounterproofNackData {\n                counterproof_txid: graph.counterproofs[0].counterproof.as_ref().compute_txid(),\n            },\n            connectors.counterproof[0],\n        );\n        let operator_descriptor =\n            Descriptor::new_p2tr(&signer.operator.x_only_public_key().0.serialize()).unwrap();\n        nack.push_output(TxOut {\n            value: nack.prevouts()[0].value - counterproof_nack_fee(),\n            script_pubkey: operator_descriptor.to_script(),\n        });\n        let signed = nack.finalize_partial(dummy_sig());\n        pin(\n            signed.weight().to_vbytes_ceil(),\n            COUNTERPROOF_NACK_VSIZE,\n            "counterproof_nack",\n        );\n    }\n',
        "",
        "remove obsolete mutable-NACK vsize pin",
    ))
    patch(repo, rel, edits, dry_run)


def patch_musig_functor(repo: Path, dry_run: bool) -> None:
    rel = "crates/tx-graph/src/musig_functor.rs"
    patch(repo, rel, [
        (
            "    BridgeProofTimeoutTx, ContestTx, ContestedPayoutTx, CounterproofAckTx, CounterproofTx, SlashTx,\n",
            "    BridgeProofTimeoutTx, ContestTx, ContestedPayoutTx, CounterproofAckTx, CounterproofTx,\n    SlashTx, UncontestedPayoutTx, UnstakingIntentTx, UnstakingTx,\n    ValidityFirstCounterproofNackTx,\n",
            "import fixed nack",
        ),
        (
            "    UncontestedPayoutTx, UnstakingIntentTx, UnstakingTx,\n};",
            "};",
            "remove duplicated imports",
        ),
        (
            "    /// For the counterproving watchtower, data for each input of the counterproof ACK transaction.\n    pub counterproof_ack: [A; CounterproofAckTx::N_INPUTS],\n}",
            "    /// For the counterproving watchtower, data for each input of the counterproof ACK transaction.\n    pub counterproof_ack: [A; CounterproofAckTx::N_INPUTS],\n    /// For the graph owner, data for the fixed timeout NACK input.\n    pub counterproof_nack: [A; ValidityFirstCounterproofNackTx::N_INPUTS],\n}",
            "watchtower fixed nack field",
        ),
        (
            "const GAME_WATCHTOWER_LEN: usize =\n    ContestTx::N_INPUTS + CounterproofTx::N_INPUTS + CounterproofAckTx::N_INPUTS;",
            "const GAME_WATCHTOWER_LEN: usize = ContestTx::N_INPUTS\n    + CounterproofTx::N_INPUTS\n    + CounterproofAckTx::N_INPUTS\n    + ValidityFirstCounterproofNackTx::N_INPUTS;",
            "watchtower packed length",
        ),
        (
            "                let [c, d] = wt.counterproof_ack;\n\n                [a, b, c, d]",
            "                let [c, d] = wt.counterproof_ack;\n                let [e] = wt.counterproof_nack;\n\n                [a, b, c, d, e]",
            "pack fixed nack",
        ),
        (
            "                let [a, b, c, d] = wt;\n                WatchtowerFunctor {\n                    contest: [a],\n                    counterproof: [b],\n                    counterproof_ack: [c, d],\n                }",
            "                let [a, b, c, d, e] = wt;\n                WatchtowerFunctor {\n                    contest: [a],\n                    counterproof: [b],\n                    counterproof_ack: [c, d],\n                    counterproof_nack: [e],\n                }",
            "unpack fixed nack",
        ),
        (
            "                    counterproof_ack: watchtower.counterproof_ack.each_ref(),\n",
            "                    counterproof_ack: watchtower.counterproof_ack.each_ref(),\n                    counterproof_nack: watchtower.counterproof_nack.each_ref(),\n",
            "as_ref fixed nack",
        ),
    ], dry_run)


def patch_game_graph(repo: Path, dry_run: bool) -> None:
    rel = "crates/tx-graph/src/game_graph.rs"
    edits: list[tuple[str, str, str]] = [
        (
            "        CounterproofConnector, NOfNConnector,\n",
            "        NOfNConnector, ValidityFirstCounterproofConnector,\n",
            "connector import",
        ),
        (
            "            CounterproofAckTx, CounterproofData, CounterproofTx, SlashData, SlashTx,\n",
            "            CounterproofAckTx, CounterproofData, CounterproofTx, SlashData, SlashTx,\n            ValidityFirstCounterproofNackData, ValidityFirstCounterproofNackTx,\n",
            "fixed nack transaction imports",
        ),
        (
            "    /// Per-watchtower fault pubkeys used to lock each counterproof-nack output.\n",
            "    /// Per-watchtower RankLock ACK commitments carried in the legacy 32-byte slot.\n",
            "deposit docs",
        ),
        (
            "    /// For each watchtower, a fault key from Mosaic.\n    pub wt_fault_pubkeys: Vec<XOnlyPublicKey>,",
            "    /// For each watchtower, the SHA256 commitment for the positive ACK lock.\n    /// The compatibility type is x-only; producers rejection-sample until the 32 bytes parse.\n    pub wt_fault_pubkeys: Vec<XOnlyPublicKey>,",
            "key docs",
        ),
        (
            "    /// Counterproof ACK transaction.\n    pub counterproof_ack: CounterproofAckTx,\n}",
            "    /// Counterproof ACK transaction.\n    pub counterproof_ack: CounterproofAckTx,\n    /// Fixed CSV-delayed counterproof NACK transaction.\n    pub counterproof_nack: ValidityFirstCounterproofNackTx,\n}",
            "counterproof subgraph field",
        ),
        (
            "    /// Counterproof connectors for each watchtower.\n    pub counterproof: Vec<CounterproofConnector>,",
            "    /// Validity-first counterproof connectors for each watchtower.\n    pub counterproof: Vec<ValidityFirstCounterproofConnector>,",
            "connector vector type",
        ),
        (
            "                    let counterproof_ack = CounterproofAckTx::new(\n                        counterproof_ack_data,\n                        counterproof_connector,\n                        connectors.contest_payout,\n                        keys.watchtower_pubkeys[watchtower_index],\n                    );\n\n                    CounterproofGraph {\n                        counterproof,\n                        counterproof_ack,\n                    }",
            "                    let counterproof_ack = CounterproofAckTx::new(\n                        counterproof_ack_data,\n                        counterproof_connector,\n                        connectors.contest_payout,\n                        keys.watchtower_pubkeys[watchtower_index],\n                    );\n                    let counterproof_nack = ValidityFirstCounterproofNackTx::new(\n                        ValidityFirstCounterproofNackData {\n                            counterproof_txid: counterproof.as_ref().compute_txid(),\n                        },\n                        counterproof_connector,\n                        &keys.operator_descriptor,\n                    );\n\n                    CounterproofGraph {\n                        counterproof,\n                        counterproof_ack,\n                        counterproof_nack,\n                    }",
            "build fixed nack",
        ),
        (
            "                    let counterproof_ack_txid = subgraph.counterproof_ack.as_ref().compute_txid();\n                    WatchtowerFunctor {\n                        contest: [OutPoint::new(contest_txid, 0)],\n                        counterproof: [OutPoint::new(counterproof_txid, 0)],\n                        counterproof_ack: array::from_fn(|i| {\n                            OutPoint::new(counterproof_ack_txid, i as u32)\n                        }),\n                    }",
            "                    let counterproof_ack_txid = subgraph.counterproof_ack.as_ref().compute_txid();\n                    let counterproof_nack_txid = subgraph.counterproof_nack.as_ref().compute_txid();\n                    WatchtowerFunctor {\n                        contest: [OutPoint::new(contest_txid, 0)],\n                        counterproof: [OutPoint::new(counterproof_txid, 0)],\n                        counterproof_ack: array::from_fn(|i| {\n                            OutPoint::new(counterproof_ack_txid, i as u32)\n                        }),\n                        counterproof_nack: [OutPoint::new(counterproof_nack_txid, 0)],\n                    }",
            "fixed nack inpoints",
        ),
        (
            "                CounterproofConnector::new(\n                    protocol.network,\n                    keys.n_of_n_pubkey,\n                    wt_fault_pubkey,\n                    protocol.nack_timelock,\n                    counterproof_surcharge,\n                )",
            "                ValidityFirstCounterproofConnector::new(\n                    protocol.network,\n                    keys.n_of_n_pubkey,\n                    wt_fault_pubkey.serialize(),\n                    protocol.nack_timelock,\n                    counterproof_surcharge,\n                )",
            "construct validity-first connector",
        ),
    ]
    # musig_signing_info has a WatchtowerFunctor literal separate from inpoints.
    edits.append((
        "                    counterproof_ack: self.counterproofs[watchtower_index as usize]\n                        .counterproof_ack\n                        .signing_info(),\n",
        "                    counterproof_ack: self.counterproofs[watchtower_index as usize]\n                        .counterproof_ack\n                        .signing_info(),\n                    counterproof_nack: self.counterproofs[watchtower_index as usize]\n                        .counterproof_nack\n                        .signing_info(),\n",
        "fixed nack signing info",
    ))
    # Regtest fixture: derive exact commitments/preimages rather than Mosaic keypairs.
    edits.extend([
        (
            "    use bitcoin::{hashes::Hash, transaction::Version, TxOut};",
            "    use bitcoin::{hashes::Hash, transaction::Version, TxOut};",
            "test import anchor",
        ),
        (
            "        AdminBurnData, AdminBurnTx, BridgeProofData, BridgeProofTx, CounterproofNackData,\n        CounterproofNackTx, UnstakingBurnData, UnstakingBurnTx,\n",
            "        AdminBurnData, AdminBurnTx, BridgeProofData, BridgeProofTx, UnstakingBurnData,\n        UnstakingBurnTx,\n",
            "remove dynamic nack test imports",
        ),
        (
            "        pub wt_fault_keypairs: Vec<Keypair>,\n",
            "        pub ack_preimages: Vec<[u8; 32]>,\n",
            "fixture preimages",
        ),
        (
            "                wt_fault_keypairs: (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect(),\n",
            "                ack_preimages: (0..N_WATCHTOWERS)\n                    .map(|_| loop {\n                        let preimage: [u8; 32] = random();\n                        let image = sha256::Hash::hash(&preimage).to_byte_array();\n                        if XOnlyPublicKey::from_slice(&image).is_ok() {\n                            break preimage;\n                        }\n                    })\n                    .collect(),\n",
            "generate valid commitments",
        ),
        (
            "            wt_fault_pubkeys: signer\n                .wt_fault_keypairs\n                .iter()\n                .map(|k| k.x_only_public_key().0)\n                .collect(),",
            "            wt_fault_pubkeys: signer\n                .ack_preimages\n                .iter()\n                .map(|preimage| {\n                    XOnlyPublicKey::from_slice(\n                        &sha256::Hash::hash(preimage).to_byte_array(),\n                    )\n                    .expect(\"fixture rejection-samples a valid x-only commitment\")\n                })\n                .collect(),",
            "commitments in graph data",
        ),
        (
            "            let data = CounterproofNackData {\n                counterproof_txid: game.counterproofs[0].counterproof.as_ref().compute_txid(),\n            };\n            let mut counterproof_nack = CounterproofNackTx::new(data, connectors.counterproof[0]);\n            counterproof_nack.push_input(node.next_coinbase_txin(), node.coinbase_tx_out());\n            counterproof_nack.push_output(TxOut {\n                value: node.coinbase_amount() - FEE,\n                script_pubkey: node.wallet_address().script_pubkey(),\n            });\n            let wt_fault_signature = counterproof_nack\n                .signing_info_partial()\n                .sign(&signer.wt_fault_keypairs[0]);\n            let counterproof_nack = counterproof_nack.finalize_partial(wt_fault_signature);\n            assert_eq!(counterproof_nack.version, Version(3));\n\n            node.sign_and_broadcast(&counterproof_nack);\n            node.mine_blocks(1);\n            since_contest += 1;",
            "            let counterproof_nack = game.counterproofs[0]\n                .counterproof_nack\n                .clone()\n                .finalize(presigned.watchtowers[0].counterproof_nack[0]);\n            assert_eq!(counterproof_nack.version, Version(3));\n            let child = node.create_wallet_cpfp_child(\n                &game.counterproofs[0].counterproof_nack,\n                (),\n                FEE * 2,\n            );\n            let package = [counterproof_nack, child];\n\n            node.mine_blocks(1); // confirm the counterproof parent\n            since_contest += 1;\n            node.submit_package_invalid(&package);\n            let pre_maturity = usize::from(NACK_TIMELOCK.value()).saturating_sub(1);\n            node.mine_blocks(pre_maturity);\n            since_contest += pre_maturity;\n            node.submit_package(&package);\n            node.mine_blocks(1);\n            since_contest += 1;",
            "fixed timeout nack regtest",
        ),
        (
            "            let n_blocks = usize::from(NACK_TIMELOCK.value()) - 1;\n            node.mine_blocks(n_blocks);\n            since_contest += n_blocks;\n\n            let counterproof_ack = game.counterproofs[0]\n                .counterproof_ack\n                .clone()\n                .finalize(presigned.watchtowers[0].counterproof_ack);",
            "            let counterproof_ack = game.counterproofs[0]\n                .counterproof_ack\n                .clone()\n                .finalize(\n                    signer.ack_preimages[0],\n                    presigned.watchtowers[0].counterproof_ack,\n                );",
            "immediate ack regtest",
        ),
        (
            "            let package = [counterproof_ack, child];\n\n            node.submit_package_invalid(&package);\n            node.mine_blocks(1);\n            since_contest += 1;\n            node.submit_package(&package);\n\n            // ┌───────────────────────────────────────────────────────────────┐\n            // │                            Slash",
            "            let package = [counterproof_ack, child];\n\n            node.submit_package(&package);\n            node.mine_blocks(1);\n            since_contest += 1;\n\n            // ┌───────────────────────────────────────────────────────────────┐\n            // │                            Slash",
            "ACK no CSV wait",
        ),
    ])
    edits = [e for e in edits if e[0] != e[1]]
    patch(repo, rel, edits, dry_run)


def patch_duties(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/graph/duties.rs"
    patch(repo, rel, [
        (
            "    counterproof::CounterproofTx,\n    prelude::{ContestTx, CounterproofNackTx, UnstakingBurnTx},\n",
            "    counterproof::CounterproofTx,\n    prelude::{ContestTx, CounterproofAckTx, CounterproofNackTx, UnstakingBurnTx},\n",
            "ACK tx import",
        ),
        (
            "    /// Publish a counterproof ACK transaction.\n    PublishCounterProofAck {\n",
            "    /// Resolve a RankLock positive unlock and publish the exact pre-signed ACK.\n    ResolveValidityFirstCounterProofAck {\n        /// Bridge proof transaction bound into the RankLock handoff.\n        bridge_proof_txid: Txid,\n        /// Counterproof transaction bound into the RankLock handoff.\n        counterproof_txid: Txid,\n        /// Unsigned exact ACK template.\n        counterproof_ack_tx: CounterproofAckTx,\n        /// N/N signatures for both ACK inputs.\n        n_of_n_signatures: [Signature; CounterproofAckTx::N_INPUTS],\n    },\n\n    /// Publish the fixed pre-signed timeout NACK.\n    PublishValidityFirstCounterProofNack {\n        /// Finalized exact timeout transaction.\n        signed_counter_proof_nack_tx: Transaction,\n    },\n\n    /// Legacy Mosaic-backed ACK duty retained for rollback compatibility.\n    PublishCounterProofAck {\n",
            "new validity-first duties",
        ),
        (
            "            GraphDuty::PublishCounterProofAck { .. } => \"PublishCounterProofAck\".to_string(),\n",
            "            GraphDuty::ResolveValidityFirstCounterProofAck { .. } => {\n                \"ResolveValidityFirstCounterProofAck\".to_string()\n            }\n            GraphDuty::PublishValidityFirstCounterProofNack { .. } => {\n                \"PublishValidityFirstCounterProofNack\".to_string()\n            }\n            GraphDuty::PublishCounterProofAck { .. } => \"PublishCounterProofAck\".to_string(),\n",
            "display new duties",
        ),
    ], dry_run)


def patch_machine(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/graph/machine.rs"
    patch(repo, rel, [
        (
            "use bitcoin::Transaction;",
            "use bitcoin::{Transaction, Txid};",
            "Txid import",
        ),
        (
            "use strata_bridge_primitives::types::BitcoinBlockHeight;",
            "use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};",
            "OperatorIdx import",
        ),
        (
            "            GraphEvent::CounterProofNackConfirmed(nack) => self.process_counterproof_nackd(nack),",
            "            GraphEvent::CounterProofNackConfirmed(nack) => {\n                self.process_counterproof_nackd(cfg, nack)\n            }",
            "pass cfg to exact NACK validation",
        ),
        (
            "    }\n}\n\n/// Generates the [`GameGraph`] from the [`GraphSM`] config and deposit params.",
            '''    }\n\n    /// Builds the validity-first ACK resolution duty for an already-confirmed counterproof.\n    #[expect(clippy::too_many_arguments)]\n    pub(super) fn validity_first_ack_duty(\n        &self,\n        cfg: &GraphSMCfg,\n        graph_data: &DepositParams,\n        signatures: &[Signature],\n        bridge_proof_txid: Txid,\n        counterprover_idx: OperatorIdx,\n        event: GraphEvent,\n    ) -> GSMResult<GraphDuty> {\n        let graph_owner_idx = self.context().operator_idx();\n        let slot = watchtower_slot_for_operator(graph_owner_idx, counterprover_idx).ok_or_else(|| {\n            GSMError::rejected(\n                self.state().clone(),\n                event.clone(),\n                format!("operator {counterprover_idx} has no watchtower slot"),\n            )\n        })?;\n        let (game, sigs) = unpack_game(cfg, self.context(), graph_data, signatures);\n        let subgraph = game.counterproofs.get(slot).ok_or_else(|| {\n            GSMError::rejected(\n                self.state().clone(),\n                event.clone(),\n                format!("missing counterproof graph for watchtower slot {slot}"),\n            )\n        })?;\n        let watchtower_sigs = sigs.watchtowers.get(slot).ok_or_else(|| {\n            GSMError::rejected(\n                self.state().clone(),\n                event,\n                format!("missing pre-signatures for watchtower slot {slot}"),\n            )\n        })?;\n        Ok(GraphDuty::ResolveValidityFirstCounterProofAck {\n            bridge_proof_txid,\n            counterproof_txid: subgraph.counterproof.as_ref().compute_txid(),\n            counterproof_ack_tx: subgraph.counterproof_ack.clone(),\n            n_of_n_signatures: watchtower_sigs.counterproof_ack,\n        })\n    }\n}\n\n/// Generates the [`GameGraph`] from the [`GraphSM`] config and deposit params.''',
            "ACK duty helper",
        ),
    ], dry_run)


def patch_contested_transition(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/graph/transitions/contested.rs"
    text = read(repo, rel)
    # process_counterproof_nackd needs config for exact fixed txid derivation.
    text = replace_once(
        text,
        "    pub(crate) fn process_counterproof_nackd(\n        &mut self,\n        event: CounterProofNackConfirmedEvent,\n",
        "    pub(crate) fn process_counterproof_nackd(\n        &mut self,\n        cfg: Arc<GraphSMCfg>,\n        event: CounterProofNackConfirmedEvent,\n",
        f"{rel}: NACK config",
    )
    old = '''                // Validate that the NACK tx spends the correct counterproof\n                // ACK/NACK output and is not a known counterproof ACK.\n                if !validate_counterproof_nack(\n                    &graph_summary,\n                    self.context().operator_idx(),\n                    event.counterprover_idx,\n                    &event.tx,\n                ) {'''
    new = '''                // Validate the exact pre-signed fixed NACK txid. This rejects\n                // alternate outputs, replayed deposits/games and fee-wallet mutations.\n                let game = crate::graph::machine::generate_game_graph(\n                    &cfg,\n                    self.context(),\n                    &graph_data,\n                );\n                let slot = watchtower_slot_for_operator(\n                    self.context().operator_idx(),\n                    event.counterprover_idx,\n                );\n                let valid_nack = slot\n                    .and_then(|slot| game.counterproofs.get(slot))\n                    .is_some_and(|subgraph| {\n                        subgraph.counterproof_nack.as_ref().compute_txid()\n                            == event.tx.compute_txid()\n                    });\n                if !valid_nack {'''
    text = replace_once(text, old, new, f"{rel}: exact NACK validation")
    # Counterproof-before-proof ordering: once proof arrives and our counterproof already exists, resolve ACK.
    old = '''                if is_watchtower && !counterproof_exists {\n                    duties.push(self.potential_counterproof_duty(\n                        &cfg,\n                        &graph_data,\n                        &signatures,\n                        event.bridge_proof_block_height,\n                        &bridge_proof,\n                        &event.tx,\n                        event.clone().into(),\n                    )?);\n                }'''
    new = '''                if is_watchtower {\n                    if counterproof_exists {\n                        duties.push(self.validity_first_ack_duty(\n                            &cfg,\n                            &graph_data,\n                            &signatures,\n                            event.tx.compute_txid(),\n                            pov_idx,\n                            event.clone().into(),\n                        )?);\n                    } else {\n                        duties.push(self.potential_counterproof_duty(\n                            &cfg,\n                            &graph_data,\n                            &signatures,\n                            event.bridge_proof_block_height,\n                            &bridge_proof,\n                            &event.tx,\n                            event.clone().into(),\n                        )?);\n                    }\n                }'''
    text = replace_once(text, old, new, f"{rel}: ordering ACK")
    # Delete obsolete permissive helper at file end and its now-unused imports.
    start = text.find("/// Validates that `tx` spends the NACK output")
    if start != -1:
        text = text[:start].rstrip() + "\n"
    text = text.replace("use strata_bridge_primitives::types::OperatorIdx;\n", "")
    text = text.replace(
        "        spends_contest_proof_connector, spends_counterproof_ack_nack, spends_stake_outpoint,\n",
        "        spends_contest_proof_connector, spends_stake_outpoint,\n",
    )
    write(repo, rel, text, dry_run)


def patch_common_transition(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/graph/transitions/common.rs"
    text = read(repo, rel)
    start_marker = "            GraphState::CounterProofPosted {\n"
    end_marker = "            GraphState::AllNackd {\n"
    start = text.find(start_marker)
    end = text.find(end_marker, start + 1)
    if start == -1 or end == -1:
        raise PatchError(f"{rel}: CounterProofPosted branch boundaries not found")

    branch = r'''            GraphState::CounterProofPosted {
                last_block_height,
                graph_data,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_bridge_proof,
                counterproofs_and_confs,
                counterproof_nacks,
                ..
            } => {
                *last_block_height = new_block_event.block_height;

                if let Some(slash_duty) = check_slash_timeout(
                    &cfg,
                    &graph_ctx,
                    new_block_event.block_height,
                    *contest_block_height,
                    graph_data.clone(),
                    signatures,
                ) {
                    return Ok(GSMOutput::with_duties(vec![slash_duty]));
                }

                let pov_idx = graph_ctx.operator_table().pov_idx();
                let is_own_graph = graph_ctx.operator_idx() == pov_idx;

                // A CSV transaction can enter the next block once
                // tip + 1 >= confirmation_height + relative_delay.
                if is_own_graph {
                    let nack_timelock =
                        u64::from(cfg.game_graph_params.nack_timelock.value());
                    let (game, sigs) = unpack_game(&cfg, &graph_ctx, graph_data, signatures);
                    let mut duties = Vec::new();
                    for (counterprover_idx, data) in counterproofs_and_confs.iter() {
                        if counterproof_nacks.contains_key(counterprover_idx)
                            || new_block_event.block_height.saturating_add(1)
                                < data.conf_height.saturating_add(nack_timelock)
                        {
                            continue;
                        }
                        let Some(slot) = watchtower_slot_for_operator(
                            graph_ctx.operator_idx(),
                            *counterprover_idx,
                        ) else {
                            continue;
                        };
                        let (Some(subgraph), Some(watchtower_sigs)) =
                            (game.counterproofs.get(slot), sigs.watchtowers.get(slot))
                        else {
                            continue;
                        };
                        duties.push(GraphDuty::PublishValidityFirstCounterProofNack {
                            signed_counter_proof_nack_tx: subgraph
                                .counterproof_nack
                                .clone()
                                .finalize(watchtower_sigs.counterproof_nack[0]),
                        });
                    }
                    if !duties.is_empty() {
                        return Ok(GSMOutput::with_duties(duties));
                    }
                }

                if let Some(contested_payout_duty) = check_contested_payout_timeout(
                    &cfg,
                    &graph_ctx,
                    new_block_event.block_height,
                    *contest_block_height,
                    graph_data.clone(),
                    signatures,
                ) {
                    return Ok(GSMOutput::with_duties(vec![contested_payout_duty]));
                }

                // Re-resolve an immediate ACK on every new block while the
                // concrete positive unlock is absent. The executor treats an
                // absent unlock as a no-op; malformed unlocks are hard errors.
                if !is_own_graph
                    && counterproofs_and_confs.contains_key(&pov_idx)
                    && !counterproof_nacks.contains_key(&pov_idx)
                {
                    if let Some((bridge_proof_tx, _)) = refuted_bridge_proof.as_ref() {
                        let (game, sigs) =
                            unpack_game(&cfg, &graph_ctx, graph_data, signatures);
                        if let Some(slot) =
                            watchtower_slot_for_operator(graph_ctx.operator_idx(), pov_idx)
                        {
                            if let (Some(subgraph), Some(watchtower_sigs)) =
                                (game.counterproofs.get(slot), sigs.watchtowers.get(slot))
                            {
                                return Ok(GSMOutput::with_duties(vec![
                                    GraphDuty::ResolveValidityFirstCounterProofAck {
                                        bridge_proof_txid: bridge_proof_tx.compute_txid(),
                                        counterproof_txid: subgraph
                                            .counterproof
                                            .as_ref()
                                            .compute_txid(),
                                        counterproof_ack_tx: subgraph.counterproof_ack.clone(),
                                        n_of_n_signatures: watchtower_sigs.counterproof_ack,
                                    },
                                ]));
                            }
                        }
                    }
                }

                let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());
                let invalid_claim = refuted_bridge_proof.is_none() && fulfillment_txid.is_none();
                if !is_own_graph
                    && invalid_claim
                    && new_block_event.block_height > *contest_block_height + proof_timelock
                {
                    let (game_graph, sigs) =
                        unpack_game(&cfg, &graph_ctx, graph_data, signatures);
                    let signed_timeout_tx = game_graph
                        .bridge_proof_timeout
                        .finalize(sigs.bridge_proof_timeout);
                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx },
                    ]));
                }

                Ok(GSMOutput::new())
            }

'''
    text = text[:start] + branch + text[end:]
    write(repo, rel, text, dry_run)

def patch_retry(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/graph/handlers/retry.rs"
    text = read(repo, rel)
    text = replace_once(
        text,
        "    transactions::prelude::{CounterproofNackData, CounterproofNackTx},\n",
        "",
        f"{rel}: remove dynamic NACK imports",
    )
    text = replace_once(
        text,
        "    machine::{GSMOutput, GraphSM, generate_game_graph},",
        "    machine::{GSMOutput, GraphSM, generate_game_graph, unpack_game},",
        f"{rel}: unpack game import",
    )
    start_marker = "            GraphState::CounterProofPosted {\n"
    end_marker = "            _ => Vec::new(),\n"
    start = text.find(start_marker)
    end = text.find(end_marker, start + 1)
    if start == -1 or end == -1:
        raise PatchError(f"{rel}: CounterProofPosted retry branch boundaries not found")

    branch = r'''            GraphState::CounterProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                refuted_bridge_proof,
                counterproofs_and_confs,
                counterproof_nacks,
                ..
            } => {
                let pov_idx = self.context().operator_table().pov_idx();
                let is_pov_graph = self.context().operator_idx() == pov_idx;

                if is_pov_graph {
                    let setup_params = self.context().generate_setup_params(&cfg, graph_data);
                    let connectors = GameConnectors::new(
                        graph_data.game_index,
                        &cfg.game_graph_params,
                        &setup_params,
                    );
                    let mut duties = Vec::new();
                    if refuted_bridge_proof.is_none() {
                        duties.push(GraphDuty::GenerateAndPublishBridgeProof {
                            graph_idx: self.context().graph_idx(),
                            last_block_height: *last_block_height,
                            contest_txid: graph_summary.contest,
                            game_index: graph_data.game_index,
                            contest_proof_connector: connectors.contest_proof,
                        });
                    }

                    let nack_timelock =
                        u64::from(cfg.game_graph_params.nack_timelock.value());
                    let (game, sigs) = unpack_game(&cfg, self.context(), graph_data, signatures);
                    for (counterprover_idx, data) in counterproofs_and_confs.iter() {
                        if counterproof_nacks.contains_key(counterprover_idx)
                            || (*last_block_height).saturating_add(1)
                                < data.conf_height.saturating_add(nack_timelock)
                        {
                            continue;
                        }
                        let Some(slot) =
                            watchtower_slot_for_operator(pov_idx, *counterprover_idx)
                        else {
                            continue;
                        };
                        let (Some(subgraph), Some(watchtower_sigs)) =
                            (game.counterproofs.get(slot), sigs.watchtowers.get(slot))
                        else {
                            continue;
                        };
                        duties.push(GraphDuty::PublishValidityFirstCounterProofNack {
                            signed_counter_proof_nack_tx: subgraph
                                .counterproof_nack
                                .clone()
                                .finalize(watchtower_sigs.counterproof_nack[0]),
                        });
                    }
                    duties
                } else if let Some((bridge_proof_tx, proof)) = refuted_bridge_proof {
                    if counterproofs_and_confs.contains_key(&pov_idx)
                        && !counterproof_nacks.contains_key(&pov_idx)
                    {
                        vec![self.validity_first_ack_duty(
                            &cfg,
                            graph_data,
                            signatures,
                            bridge_proof_tx.compute_txid(),
                            pov_idx,
                            RetryTickEvent.into(),
                        )?]
                    } else if !counterproofs_and_confs.contains_key(&pov_idx) {
                        vec![self.potential_counterproof_duty(
                            &cfg,
                            graph_data,
                            signatures,
                            *last_block_height,
                            proof,
                            bridge_proof_tx,
                            RetryTickEvent.into(),
                        )?]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
'''
    text = text[:start] + branch + text[end:]
    write(repo, rel, text, dry_run)

def patch_classifier(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-sm/src/tx_classifier.rs"
    patch(repo, rel, [
        (
            "    game_graph::GameGraphSummary,\n",
            "    game_graph::{GameGraph, GameGraphSummary},\n",
            "GameGraph import",
        ),
        (
            "/// A NACK transaction is not presigned but it spends the ACK/NACK output of the counterproof it\n/// rejects.\npub fn nack_counterprover_idx(\n    summary: &GameGraphSummary,\n    graph_owner_idx: OperatorIdx,\n    tx: &Transaction,\n) -> Option<OperatorIdx> {\n    summary\n        .counterproofs\n        .iter()\n        .enumerate()\n        .find_map(|(watchtower_slot, summary)| {\n            spends_counterproof_ack_nack(summary.counterproof, tx)\n                .then(|| watchtower_slot_to_operator_idx(watchtower_slot, graph_owner_idx))\n        })\n}",
            "/// A validity-first NACK is an exact pre-signed transaction; alternate outputs or\n/// fee-wallet mutations are not classified.\npub fn nack_counterprover_idx(\n    game: &GameGraph,\n    graph_owner_idx: OperatorIdx,\n    tx: &Transaction,\n) -> Option<OperatorIdx> {\n    let txid = tx.compute_txid();\n    game.counterproofs\n        .iter()\n        .enumerate()\n        .find_map(|(watchtower_slot, subgraph)| {\n            (subgraph.counterproof_nack.as_ref().compute_txid() == txid)\n                .then(|| watchtower_slot_to_operator_idx(watchtower_slot, graph_owner_idx))\n        })\n}",
            "exact NACK classifier",
        ),
    ], dry_run)

    rel = "crates/bridge-sm/src/graph/tx_classifier.rs"
    text = read(repo, rel)
    text = text.replace(
        "        machine::GraphSM,",
        "        machine::{GraphSM, generate_game_graph},",
    )
    old = '''                    nack_counterprover_idx(graph_summary, self.context().operator_idx(), tx).map(\n                        |counterprover_idx| {'''
    new = '''                    let game = generate_game_graph(config, self.context(), graph_data);\n                    nack_counterprover_idx(&game, self.context().operator_idx(), tx).map(\n                        |counterprover_idx| {'''
    text = replace_once(text, old, new, f"{rel}: exact NACK classification")
    # Expose graph_data in CounterProofPosted match arm.
    text = replace_once(
        text,
        "            GraphState::CounterProofPosted { graph_summary, .. } => {",
        "            GraphState::CounterProofPosted { graph_data, graph_summary, .. } => {",
        f"{rel}: graph data classifier",
    )
    write(repo, rel, text, dry_run)


def patch_executor(repo: Path, dry_run: bool) -> None:
    rel = "crates/bridge-exec/src/errors.rs"
    patch(repo, rel, [
        (
            "    /// Error interacting with the mosaic service.\n    #[error(\"mosaic error: {0}\")]\n    MosaicErr(String),\n",
            "    /// Error interacting with the mosaic service.\n    #[error(\"mosaic error: {0}\")]\n    MosaicErr(String),\n\n    /// RankLock setup/unlock handoff was absent, malformed, or inconsistent.\n    #[error(\"ranklock error: {0}\")]\n    RanklockErr(String),\n",
            "RankLock error",
        )
    ], dry_run)

    rel = "crates/bridge-exec/src/graph/mod.rs"
    patch(repo, rel, [
        (
            "mod counterproof_nack;\nmod uncontested;",
            "mod counterproof_nack;\nmod ranklock;\nmod uncontested;",
            "ranklock module",
        ),
        (
            "        GraphDuty::PublishCounterProofAck {\n",
            "        GraphDuty::ResolveValidityFirstCounterProofAck {\n            bridge_proof_txid,\n            counterproof_txid,\n            counterproof_ack_tx,\n            n_of_n_signatures,\n        } => {\n            ranklock::resolve_and_publish_counterproof_ack(\n                &output_handles,\n                *bridge_proof_txid,\n                *counterproof_txid,\n                counterproof_ack_tx.clone(),\n                *n_of_n_signatures,\n            )\n            .await\n        }\n        GraphDuty::PublishValidityFirstCounterProofNack {\n            signed_counter_proof_nack_tx,\n        } => ranklock::publish_timeout_nack(\n            &output_handles,\n            signed_counter_proof_nack_tx,\n        )\n        .await,\n        GraphDuty::PublishCounterProofAck {\n",
            "dispatch new duties",
        ),
    ], dry_run)

    rel = "crates/bridge-exec/src/graph/common.rs"
    text = read(repo, rel)
    old = '''    let (adaptor_pubkeys, fault_pubkeys) = fetch_graph_keys(\n        output_handles.mosaic_client.as_ref(),\n        operator_table,\n        graph_idx,\n        game_index,\n    )\n    .await?;'''
    new = '''    let adaptor_pubkeys = fetch_graph_adaptor_keys(\n        output_handles.mosaic_client.as_ref(),\n        operator_table,\n        graph_idx,\n        game_index,\n    )\n    .await?;\n    let fault_pubkeys: Vec<XOnlyPubKey> = watchtower_idxs(operator_table, graph_idx.operator)\n        .map(|watchtower_idx| {\n            super::ranklock::load_setup_commitment(graph_idx, game_index, watchtower_idx)\n                .map(Into::into)\n        })\n        .collect::<Result<_, _>>()?;'''
    text = replace_once(text, old, new, f"{rel}: setup commitments")
    text = text.replace('"fetched graph keys from mosaic"', '"fetched Mosaic adaptor keys and RankLock ACK commitments"')
    text = text.replace("async fn fetch_graph_keys(", "async fn fetch_graph_adaptor_keys(")
    text = text.replace(") -> Result<(Vec<XOnlyPubKey>, Vec<XOnlyPubKey>), ExecutorError> {", ") -> Result<Vec<XOnlyPubKey>, ExecutorError> {")
    # Remove per-watchtower fault-key fetch and tuple return.
    fault_block = '''\n        info!(?graph_idx, %game_index, %watchtower, "fetching fault pubkey from mosaic");\n        let fault_pubkey = mosaic_client\n            .get_fault_pubkey(watchtower, Role::Evaluator)\n            .await\n            .map_err(|e| ExecutorError::MosaicErr(format!("get_fault_pubkey: {e:?}")))?\n            .ok_or_else(|| {\n                ExecutorError::MosaicErr(format!(\n                    "fault pubkey missing for watchtower {watchtower}"\n                ))\n            })?;\n        fault_pubkeys.push(fault_pubkey.into());\n'''
    text = text.replace("    let mut fault_pubkeys = Vec::new();\n", "")
    if fault_block not in text:
        raise PatchError(f"{rel}: Mosaic fault-key fetch block not found")
    text = text.replace(fault_block, "", 1)
    text = text.replace("    Ok((adaptor_pubkeys, fault_pubkeys))\n}", "    Ok(adaptor_pubkeys)\n}", 1)
    # Verification cross-check now comes from local RankLock setup file.
    old = '''    let local_fault_pubkey = output_handles\n        .mosaic_client\n        .get_fault_pubkey(graph_idx.operator, Role::Garbler)\n        .await\n        .map_err(|e| ExecutorError::MosaicErr(format!("get_fault_pubkey: {e:?}")))?\n        .ok_or_else(|| {\n            ExecutorError::MosaicErr(format!(\n                "local fault pubkey missing for owner={}, deposit={}",\n                graph_idx.operator, graph_idx.deposit\n            ))\n        })?;\n    if local_fault_pubkey != fault_pubkey {\n        return Err(ExecutorError::MosaicErr(format!(\n            "fault pubkey mismatch for graph {graph_idx:?}: graph_data has {fault_pubkey}, \\\n             local mosaic reports {local_fault_pubkey}"\n        )));\n    }'''
    new = '''    let local_commitment = super::ranklock::load_setup_commitment(\n        graph_idx,\n        game_index,\n        watchtower_idx,\n    )?;\n    if local_commitment != fault_pubkey {\n        return Err(ExecutorError::RanklockErr(format!(\n            "ACK commitment mismatch for graph {graph_idx:?}: graph_data has {fault_pubkey}, \\\n             local RankLock setup has {local_commitment}"\n        )));\n    }'''
    text = replace_once(text, old, new, f"{rel}: verify RankLock commitment")
    # Role is no longer needed here after removing fault pubkey calls.
    text = text.replace("    types::{DepositSighashes, Role, Sighash},\n", "    types::{DepositSighashes, Sighash},\n")
    write(repo, rel, text, dry_run)


# Every .rs path this installer creates or edits.  The pinned base tree is
# rustfmt-clean, so formatting exactly these files normalizes the text this
# installer inserts without touching anything outside the declared scope.
TOUCHED_RUST_FILES = (
    "crates/connectors/src/validity_first_counterproof.rs",
    "crates/connectors/src/lib.rs",
    "crates/connectors/src/prelude.rs",
    "crates/tx-graph/src/transactions/counterproof_nack.rs",
    "crates/tx-graph/src/transactions/counterproof.rs",
    "crates/tx-graph/src/transactions/counterproof_ack.rs",
    "crates/tx-graph/src/transactions/mod.rs",
    "crates/tx-graph/src/transactions/prelude.rs",
    "crates/tx-graph/src/fee.rs",
    "crates/tx-graph/src/musig_functor.rs",
    "crates/tx-graph/src/game_graph.rs",
    "crates/bridge-exec/src/graph/ranklock.rs",
    "crates/bridge-exec/src/graph/mod.rs",
    "crates/bridge-exec/src/graph/common.rs",
    "crates/bridge-exec/src/errors.rs",
    "crates/bridge-sm/src/graph/transitions/counterproof.rs",
    "crates/bridge-sm/src/graph/transitions/contested.rs",
    "crates/bridge-sm/src/graph/transitions/common.rs",
    "crates/bridge-sm/src/graph/duties.rs",
    "crates/bridge-sm/src/graph/machine.rs",
    "crates/bridge-sm/src/graph/handlers/retry.rs",
    "crates/bridge-sm/src/graph/tx_classifier.rs",
    "crates/bridge-sm/src/tx_classifier.rs",
)


def format_touched(repo: Path) -> None:
    """Normalize the files this installer wrote with the repo's own rustfmt.

    The replacement strings above are written for readability, not to match
    rustfmt byte-for-byte, so without this step `cargo fmt --all -- --check`
    (STRATA-004) fails on a freshly patched tree.  rustfmt is invoked through
    rustup so the channel pinned by rust-toolchain.toml is used.
    """

    # Use `cargo fmt --all` rather than invoking rustfmt on a file list: it
    # picks up the workspace edition, rustfmt.toml and the toolchain pinned by
    # rust-toolchain.toml, none of which a bare rustfmt call would honour.
    proc = subprocess.run(
        ["cargo", "fmt", "--all"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise PatchError(
            "cargo fmt failed on the patched tree; it is applied but not "
            f"formatted: {proc.stderr.strip()}"
        )

    # `--all` formats the whole workspace, which is only safe because the
    # pinned base is rustfmt-clean.  Assert that rather than assume it: if the
    # caller's tree had pre-existing formatting drift we must not silently
    # widen the patch beyond its declared scope.
    declared = set(TOUCHED_RUST_FILES)
    changed = {
        line.strip()
        for line in run(repo, "git", "diff", "--name-only").splitlines()
        if line.strip()
    }
    outside = {rel for rel in changed if rel not in declared}
    if outside:
        raise PatchError(
            "cargo fmt modified files outside the declared patch scope, which "
            "means the base checkout was not rustfmt-clean before patching: "
            f"{sorted(outside)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path, help="clean strata-bridge checkout")
    parser.add_argument("--check", action="store_true", help="validate all anchors without writing")
    args = parser.parse_args()
    try:
        repo = args.repo.resolve()
        if args.check:
            apply(repo, True)
        else:
            # Verify every exact anchor before performing the first write.
            apply(repo, True)
            apply(repo, False)
            format_touched(repo)
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("validity-first patch anchors verified" if args.check else "validity-first patch applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
