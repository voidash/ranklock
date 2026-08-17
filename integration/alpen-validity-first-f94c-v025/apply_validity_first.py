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


def replace_exactly(text: str, old: str, new: str, count: int, label: str) -> str:
    """Replace an anchor that is expected to appear exactly ``count`` times.

    ``replace_once`` deliberately refuses ambiguous anchors.  Some edits are
    genuinely repeated -- the same obsolete assertion in several tests -- and
    for those the count is stated explicitly so an unexpected extra or missing
    occurrence still fails loudly.
    """

    found = text.count(old)
    if found != count:
        raise PatchError(f"{label}: expected {count} matches, found {found}")
    return text.replace(old, new)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise PatchError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def patch(repo: Path, rel: str, edits: list[tuple[str, str, str]], dry_run: bool) -> None:
    text = read(repo, rel)
    for edit in edits:
        if len(edit) == 4:
            old, new, label, count = edit
            text = replace_exactly(text, old, new, count, f"{rel}: {label}")
        else:
            old, new, label = edit
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
    patch_bridge_sm_shared_test_fixtures(repo, dry_run)
    patch_notify_new_block_test(repo, dry_run)
    patch_bridge_sm_nack_tests(repo, dry_run)
    patch_base_logging_defect(repo, dry_run)
    patch_base_p2p_address_collision(repo, dry_run)

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
        # The test module keeps its own copy of the packed length, independent
        # of GAME_WATCHTOWER_LEN above.  Widening only the production constant
        # left every functor fixture one element short per watchtower, so
        # `unpack` returned None and the `expect("enough data")` in
        # `get_functor` panicked -- poisoning the shared LazyLock fixtures and
        # cascading into 21 of the crate's 46 lib tests.  Verified against the
        # pinned base, which is 46/0 before the patch.
        (
            "        + (ContestTx::N_INPUTS + CounterproofTx::N_INPUTS + CounterproofAckTx::N_INPUTS)\n"
            "            * N_WATCHTOWERS;",
            "        + (ContestTx::N_INPUTS\n"
            "            + CounterproofTx::N_INPUTS\n"
            "            + CounterproofAckTx::N_INPUTS\n"
            "            + ValidityFirstCounterproofNackTx::N_INPUTS)\n"
            "            * N_WATCHTOWERS;",
            "test packed length includes the fixed nack",
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
    # `validate_counterproof_nack` was the last user of `Transaction` here.
    text = replace_once(
        text,
        "use bitcoin::Transaction;\nuse strata_bridge_tx_graph::game_graph::",
        "use strata_bridge_tx_graph::game_graph::",
        f"{rel}: drop unused Transaction import",
    )
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
    # Stale tests retargeted to validity-first semantics: the ACK duty now
    # carries an unsigned template, and the NACK is CSV-gated rather than
    # emitted immediately on counterproof.  The shared fixture module is in
    # scope because the exact pre-signed transactions the state machine now
    # compares against can only be reproduced from a stable config.
    "crates/bridge-sm/src/graph/tests/mod.rs",
    "crates/bridge-sm/src/graph/tests/tx_classifier.rs",
    "crates/bridge-sm/src/graph/tests/contested/process_bridge_proof.rs",
    "crates/bridge-sm/src/graph/tests/notify_new_block.rs",
    "crates/bridge-sm/src/graph/tests/contested/process_counterproof.rs",
    "crates/bridge-sm/src/graph/tests/handlers/process_retry_tick.rs",
    "crates/bridge-sm/src/graph/tests/contested/process_counterproof_nackd.rs",
    # Base defects, not validity-first changes.  See patch_base_logging_defect
    # and patch_base_p2p_address_collision.
    "crates/common/src/logging.rs",
    "crates/p2p-service/src/tests/common.rs",
    # P4 witness check, applied from pending/p4-complete.diff.
    "crates/bridge-sm/src/graph/events.rs",
    "crates/bridge-sm/src/graph/tests/mod.rs",
    "crates/bridge-sm/src/graph/tests/contested/process_counterproof_ack.rs",
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


def patch_bridge_sm_shared_test_fixtures(repo: Path, dry_run: bool) -> None:
    """Retarget the shared bridge-sm graph-test fixtures to validity-first.

    Three things changed under the hood and every fixture that builds an exact
    transaction depends on them:

    1. ``test_graph_sm_cfg()`` randomized ``payout_descs`` and ``admin.pubkeys``
       on every call.  Those feed ``KeyData``, so two independently constructed
       configs produce two different game graphs.  That was harmless while the
       state machine only compared summary txids, but validity-first accepts and
       emits *exact* pre-signed transactions -- the fixed NACK even pays to the
       graph owner's payout descriptor -- so a fixture graph and the state
       machine's graph must come from byte-identical config.  The config is now
       memoized, exactly as the per-deposit key fixtures beside it already were.
    2. ``test_counterproof_nack_tx()`` hand-rolled a spend of the ACK/NACK
       outpoint.  The classifier now recognizes the NACK by exact txid only, so
       the fixture returns the real fixed template.
    3. Two new shared expectations, ``expected_validity_first_ack_duty`` and
       ``expected_validity_first_nack_duty``, derive the new duties the same way
       the state machine derives them, so no test hard-codes an observed value.

    The exhaustive classifier test and the late-bridge-proof watchtower test are
    retargeted here for the same reasons.
    """

    # crates/bridge-sm/src/graph/tests/mod.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/mod.rs',
        [
            ('};\n\nuse bitcoin::{\n    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn,\n    hashes::{Hash, sha256},\n    relative,\n};\n', '};\n\nuse bitcoin::{\n    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, Txid,\n    hashes::{Hash, sha256},\n    relative,\n};\n', 'shared validity-first fixtures 1'),
            ('        ProtocolParams,\n    },\n    musig_functor::GameFunctor,\n    transactions::prelude::{ClaimTx, ContestTx, CounterproofTx},\n};\nuse strata_mosaic_client_api::types::CompletedSignatures;\nuse strata_predicate::PredicateKey;\n', '        ProtocolParams,\n    },\n    musig_functor::GameFunctor,\n    transactions::prelude::{ClaimTx, ContestTx},\n};\nuse strata_mosaic_client_api::types::CompletedSignatures;\nuse strata_predicate::PredicateKey;\n', 'shared validity-first fixtures 2'),
            ('\n// ===== Configuration Helpers =====\n\n/// Creates a test bridge-wide GSM configuration.\npub(super) fn test_graph_sm_cfg() -> Arc<GraphSMCfg> {\n    let payout_descs = (0..N_TEST_OPERATORS).map(|_| random_p2tr_desc()).collect();\n\n    Arc::new(GraphSMCfg {\n        game_graph_params: ProtocolParams {\n            network: Network::Regtest,\n            magic_bytes: TEST_MAGIC_BYTES.into(),\n            contest_timelock: CONTEST_TIMELOCK,\n            proof_timelock: PROOF_TIMELOCK,\n            ack_timelock: ACK_TIMELOCK,\n            nack_timelock: NACK_TIMELOCK,\n            contested_payout_timelock: CONTESTED_PAYOUT_TIMELOCK,\n            counterproof_n_data: NonZero::new(128).unwrap(),\n            deposit_amount: TEST_DEPOSIT_AMOUNT,\n            stake_amount: STAKE_AMOUNT,\n        },\n        admin: AdminMultisig {\n            pubkeys: vec![generate_xonly_pubkey()],\n            threshold: 1,\n        },\n        operator_fee: TEST_OPERATOR_FEE,\n        payout_descs,\n        bridge_proof_predicate: PredicateKey::always_accept(),\n        counterproof_predicate: PredicateKey::always_accept(),\n    })\n}\n\n/// Creates a GraphSM for a POV operator.\n', "\n// ===== Configuration Helpers =====\n\n/// The single bridge-wide GSM configuration shared by every `test_graph_sm_cfg()` caller.\n///\n/// The randomized fields (`payout_descs`, `admin.pubkeys`) feed `KeyData` and therefore the\n/// txid of every transaction in the generated game graph. Under validity-first the state\n/// machine accepts and emits *exact* pre-signed transactions -- notably the fixed\n/// counterproof NACK, which pays to the graph owner's payout descriptor -- so a fixture\n/// that builds its expectation from one `test_graph_sm_cfg()` while the state machine runs\n/// on another must see byte-identical config. Memoizing mirrors what `TEST_ADAPTOR_PUBKEYS`\n/// and `TEST_FAULT_PUBKEYS` below already do for the per-deposit keys. Tests that need a\n/// variant still clone this value and mutate the clone.\nstatic TEST_GRAPH_SM_CFG: OnceLock<Arc<GraphSMCfg>> = OnceLock::new();\n\n/// Creates a test bridge-wide GSM configuration.\npub(super) fn test_graph_sm_cfg() -> Arc<GraphSMCfg> {\n    TEST_GRAPH_SM_CFG\n        .get_or_init(|| {\n            let payout_descs = (0..N_TEST_OPERATORS).map(|_| random_p2tr_desc()).collect();\n\n            Arc::new(GraphSMCfg {\n                game_graph_params: ProtocolParams {\n                    network: Network::Regtest,\n                    magic_bytes: TEST_MAGIC_BYTES.into(),\n                    contest_timelock: CONTEST_TIMELOCK,\n                    proof_timelock: PROOF_TIMELOCK,\n                    ack_timelock: ACK_TIMELOCK,\n                    nack_timelock: NACK_TIMELOCK,\n                    contested_payout_timelock: CONTESTED_PAYOUT_TIMELOCK,\n                    counterproof_n_data: NonZero::new(128).unwrap(),\n                    deposit_amount: TEST_DEPOSIT_AMOUNT,\n                    stake_amount: STAKE_AMOUNT,\n                },\n                admin: AdminMultisig {\n                    pubkeys: vec![generate_xonly_pubkey()],\n                    threshold: 1,\n                },\n                operator_fee: TEST_OPERATOR_FEE,\n                payout_descs,\n                bridge_proof_predicate: PredicateKey::always_accept(),\n                counterproof_predicate: PredicateKey::always_accept(),\n            })\n        })\n        .clone()\n}\n\n/// Creates a GraphSM for a POV operator.\n", 'shared validity-first fixtures 3'),
            ('    )\n}\n\npub(super) fn test_counterproof_nack_tx() -> Transaction {\n    generate_spending_tx(\n        OutPoint {\n            txid: test_graph_summary().counterproofs[0].counterproof,\n            vout: CounterproofTx::ACK_NACK_VOUT,\n        },\n        &[],\n    )\n}\n\npub(super) fn test_deposit_spend_tx() -> Transaction {\n', "    )\n}\n\n/// The exact fixed counterproof NACK for watchtower slot 0 of the POV operator's graph.\n///\n/// Validity-first made the NACK a fixed, pre-signed transaction and the state machine now\n/// recognizes it by exact txid, so a hand-rolled spend of the ACK/NACK outpoint is (rightly)\n/// no longer classified. The witness does not contribute to the txid, so the unsigned\n/// template is sufficient for classification.\npub(super) fn test_counterproof_nack_tx() -> Transaction {\n    machine::generate_game_graph(\n        &test_graph_sm_cfg(),\n        &test_graph_sm_ctx(),\n        &test_deposit_params(),\n    )\n    .counterproofs[0]\n        .counterproof_nack\n        .as_ref()\n        .clone()\n}\n\npub(super) fn test_deposit_spend_tx() -> Transaction {\n", 'shared validity-first fixtures 4'),
            ('    }\n}\n\n/// Creates test musig signers for the operators.\npub(super) fn test_operator_signers(num_signers: usize) -> Vec<TestMusigSigner> {\n    (0..num_signers)\n', '    }\n}\n\n/// The [`GraphDuty::ResolveValidityFirstCounterProofAck`] a counterproving watchtower is\n/// expected to emit for its own confirmed counterproof.\n///\n/// Validity-first makes the ACK immediate and unconditional on the NACK timelock: the duty\n/// carries the *unsigned* exact ACK template plus its N/N signatures, and the executor\n/// finalizes it only once the RankLock positive unlock resolves. Everything here is derived\n/// exactly as [`GraphSM::validity_first_ack_duty`] derives it -- same context, same config,\n/// same signature vector -- so nothing is hard-coded from observed output.\npub(super) fn expected_validity_first_ack_duty(\n    cfg: &GraphSMCfg,\n    sm: &GraphSM,\n    signatures: &[Signature],\n    bridge_proof_txid: Txid,\n) -> GraphDuty {\n    let (game_graph, sigs, slot) = pov_watchtower_slot_data(cfg, sm, signatures);\n\n    GraphDuty::ResolveValidityFirstCounterProofAck {\n        bridge_proof_txid,\n        counterproof_txid: game_graph.counterproofs[slot]\n            .counterproof\n            .as_ref()\n            .compute_txid(),\n        counterproof_ack_tx: game_graph.counterproofs[slot].counterproof_ack.clone(),\n        n_of_n_signatures: sigs.watchtowers[slot].counterproof_ack,\n    }\n}\n\n/// The [`GraphDuty::PublishValidityFirstCounterProofNack`] the graph owner is expected to\n/// emit once the NACK\'s CSV delay has matured for `counterprover_idx`.\n///\n/// The NACK is a fixed, exact, pre-signed transaction, so the expectation must be finalized\n/// with the signature taken from the very `signatures` vector held in the state under test.\npub(super) fn expected_validity_first_nack_duty(\n    cfg: &GraphSMCfg,\n    sm: &GraphSM,\n    signatures: &[Signature],\n    counterprover_idx: OperatorIdx,\n) -> GraphDuty {\n    let game_graph = machine::generate_game_graph(cfg, sm.context(), &test_deposit_params());\n    let sigs = GameFunctor::unpack(signatures.to_vec(), sm.context().watchtower_pubkeys().len())\n        .expect("signature layout matches watchtower count");\n    let slot = watchtower_slot_for_operator(sm.context().operator_idx(), counterprover_idx)\n        .expect("counterprover must have a watchtower slot");\n\n    GraphDuty::PublishValidityFirstCounterProofNack {\n        signed_counter_proof_nack_tx: game_graph.counterproofs[slot]\n            .counterproof_nack\n            .clone()\n            .finalize(sigs.watchtowers[slot].counterproof_nack[0]),\n    }\n}\n\n/// Generates the game graph, unpacks `signatures`, and resolves the watchtower slot that the\n/// POV operator occupies in the graph owned by `sm`\'s operator.\nfn pov_watchtower_slot_data(\n    cfg: &GraphSMCfg,\n    sm: &GraphSM,\n    signatures: &[Signature],\n) -> (GameGraph, GameFunctor<Signature>, usize) {\n    let game_graph = machine::generate_game_graph(cfg, sm.context(), &test_deposit_params());\n    let sigs = GameFunctor::unpack(signatures.to_vec(), sm.context().watchtower_pubkeys().len())\n        .expect("signature layout matches watchtower count");\n    let slot = watchtower_slot_for_operator(\n        sm.context().operator_idx(),\n        sm.context().operator_table().pov_idx(),\n    )\n    .expect("non-pov operator must have a watchtower slot");\n\n    (game_graph, sigs, slot)\n}\n\n/// Creates test musig signers for the operators.\npub(super) fn test_operator_signers(num_signers: usize) -> Vec<TestMusigSigner> {\n    (0..num_signers)\n', 'shared validity-first fixtures 5'),
        ],
        dry_run,
    )

    # crates/bridge-sm/src/graph/tests/tx_classifier.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/tx_classifier.rs',
        [
            ('    };\n    use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};\n    use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};\n    use strata_bridge_tx_graph::{\n        game_graph::{CounterproofGraphSummary, GameGraphSummary},\n        transactions::prelude::CounterproofTx,\n    };\n\n    use crate::{\n        graph::{\n            context::GraphSMCtx,\n            machine::GraphSM,\n            state::GraphState,\n            tests::{mock_states::*, *},\n        },\n', '    };\n    use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};\n    use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};\n    use strata_bridge_tx_graph::game_graph::{CounterproofGraphSummary, GameGraphSummary};\n\n    use crate::{\n        graph::{\n            context::GraphSMCtx,\n            machine::{GraphSM, generate_game_graph},\n            state::GraphState,\n            tests::{mock_states::*, *},\n        },\n', 'exact fixed NACK in classifier tests 1'),
            ('            _ => panic!("expected Some(CounterProofAckConfirmed) but got {ack_result:?}"),\n        }\n\n        let nack_tx = generate_spending_tx(\n            OutPoint {\n                txid: counterproof_txs[counterproof_slot].compute_txid(),\n                vout: CounterproofTx::ACK_NACK_VOUT,\n            },\n            &[],\n        );\n        let nack_result = counterproof_posted_sm.classify_tx(&cfg, &nack_tx, LATER_BLOCK_HEIGHT);\n        match nack_result {\n            Some(GraphEvent::CounterProofNackConfirmed(event)) => {\n', '            _ => panic!("expected Some(CounterProofAckConfirmed) but got {ack_result:?}"),\n        }\n\n        // Validity-first recognizes a NACK only by the exact txid of the fixed, pre-signed\n        // transaction, so the fixture must build the real template rather than an arbitrary\n        // spend of the ACK/NACK outpoint. It is derived from the same config and context the\n        // classifier itself regenerates the graph from.\n        let nack_tx = generate_game_graph(\n            &cfg,\n            counterproof_posted_sm.context(),\n            &test_deposit_params(),\n        )\n        .counterproofs[counterproof_slot]\n            .counterproof_nack\n            .as_ref()\n            .clone();\n        let nack_result = counterproof_posted_sm.classify_tx(&cfg, &nack_tx, LATER_BLOCK_HEIGHT);\n        match nack_result {\n            Some(GraphEvent::CounterProofNackConfirmed(event)) => {\n', 'exact fixed NACK in classifier tests 2'),
        ],
        dry_run,
    )

    # crates/bridge-sm/src/graph/tests/contested/process_bridge_proof.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/contested/process_bridge_proof.rs',
        [
            ('        state::{CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n            create_nonpov_sm, create_sm, dummy_proof_receipt, expected_potential_counterproof_duty,\n            get_state, mock_game_signatures,\n            mock_states::{\n                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,\n                bridge_proof_posted_state, contested_state, contested_state_with,\n                counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,\n', '        state::{CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n            create_nonpov_sm, create_sm, dummy_proof_receipt, expected_potential_counterproof_duty,\n            expected_validity_first_ack_duty, get_state, mock_game_signatures,\n            mock_states::{\n                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,\n                bridge_proof_posted_state, contested_state, contested_state_with,\n                counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,\n', 'late bridge proof resolves ACK 1'),
            ('            completed_signatures: test_completed_signatures(),\n        },\n    );\n\n    let from_state = GraphState::CounterProofPosted {\n        last_block_height: LATER_BLOCK_HEIGHT,\n        graph_data: test_deposit_params(),\n        graph_summary: TEST_GRAPH_SUMMARY.clone(),\n        signatures: Default::default(),\n        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n        contest_block_height: LATER_BLOCK_HEIGHT,\n        refuted_bridge_proof: None,\n        counterproofs_and_confs: counterproofs_and_confs.clone(),\n', '            completed_signatures: test_completed_signatures(),\n        },\n    );\n\n    // Validity-first inverts the polarity: the watchtower still does not re-post a\n    // counterproof it has already posted, but the arrival of the (late, invalid) bridge\n    // proof is exactly what completes the RankLock handoff, so it now resolves the\n    // immediate ACK instead of emitting nothing. The "skips counterproof" premise is\n    // preserved -- no PotentialCounterProof duty appears.\n    let sm = create_nonpov_sm(counter_proof_posted_without_refuted_proof_state());\n    let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n    let signatures = mock_game_signatures(&game_graph);\n    let expected_duty =\n        expected_validity_first_ack_duty(&cfg, &sm, &signatures, event.tx.compute_txid());\n\n    let from_state = GraphState::CounterProofPosted {\n        last_block_height: LATER_BLOCK_HEIGHT,\n        graph_data: test_deposit_params(),\n        graph_summary: TEST_GRAPH_SUMMARY.clone(),\n        signatures: signatures.clone(),\n        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n        contest_block_height: LATER_BLOCK_HEIGHT,\n        refuted_bridge_proof: None,\n        counterproofs_and_confs: counterproofs_and_confs.clone(),\n', 'late bridge proof resolves ACK 2'),
            ('            expected_state: GraphState::CounterProofPosted {\n                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,\n                graph_data: test_deposit_params(),\n                graph_summary: TEST_GRAPH_SUMMARY.clone(),\n                signatures: vec![],\n                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n                contest_block_height: LATER_BLOCK_HEIGHT,\n                refuted_bridge_proof: Some((event_tx, dummy_proof_receipt())),\n                counterproofs_and_confs,\n                counterproof_nacks: BTreeMap::new(),\n                stake_spent: None,\n                payout_connector_spent: None,\n            },\n            expected_duties: vec![],\n            expected_signals: vec![],\n        },\n    );\n}\n', '            expected_state: GraphState::CounterProofPosted {\n                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,\n                graph_data: test_deposit_params(),\n                graph_summary: TEST_GRAPH_SUMMARY.clone(),\n                signatures,\n                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n                contest_block_height: LATER_BLOCK_HEIGHT,\n                refuted_bridge_proof: Some((event_tx, dummy_proof_receipt())),\n                counterproofs_and_confs,\n                counterproof_nacks: BTreeMap::new(),\n                stake_spent: None,\n                payout_connector_spent: None,\n            },\n            expected_duties: vec![expected_duty],\n            expected_signals: vec![],\n        },\n    );\n}\n', 'late bridge proof resolves ACK 3'),
        ],
        dry_run,
    )


def patch_notify_new_block_test(repo: Path, dry_run: bool) -> None:
    """Retarget the ``notify_new_block`` tests that assert the old polarity.

    Under validity-first the state machine emits
    ``ResolveValidityFirstCounterProofAck`` carrying the *unsigned* exact
    template plus its N/N signatures; the executor finalizes only after the
    RankLock positive unlock resolves.  The legacy ``PublishCounterProofAck``
    variant is retained for rollback compatibility but is no longer produced on
    this path.

    The timelock also moved.  The ACK is now immediate, so the two
    ``ack_not_viable_*`` tests asserted a premise that no longer exists; rather
    than drop them, one becomes the immediate-ACK assertion at the same height
    and the other is repurposed into the assertion the new semantics actually
    needs -- that the graph owner withholds the fixed NACK until its CSV delay
    matures.  The owner and POV cases additionally need real signature vectors
    because the owner branch unpacks them before reaching its timeout checks.
    """

    # crates/bridge-sm/src/graph/tests/notify_new_block.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/notify_new_block.rs',
        [
            ('            machine::{GraphSM, generate_game_graph},\n            state::{CounterproofData, GraphState},\n            tests::{\n                CLAIM_BLOCK_HEIGHT, CONTEST_TIMELOCK_BLOCKS, GraphInvalidTransition,\n                GraphTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n                TEST_POV_IDX, create_nonpov_sm, create_sm, get_state, mock_game_signatures,\n                mock_states::{\n                    TEST_FULFILLMENT_TXID, acked_state, all_nackd_state, all_nackd_state_with,\n                    assigned_state, bridge_proof_posted_state_with,\n                    bridge_proof_timedout_state_with, claimed_state, contested_state_with,\n                    counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,\n                },\n                test_completed_signatures, test_deposit_params, test_graph_invalid_transition,\n                test_graph_sm_cfg, test_graph_sm_ctx, test_graph_summary, test_graph_transition,\n', '            machine::{GraphSM, generate_game_graph},\n            state::{CounterproofData, GraphState},\n            tests::{\n                CLAIM_BLOCK_HEIGHT, CONTEST_TIMELOCK_BLOCKS, GraphInvalidTransition,\n                GraphTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n                TEST_POV_IDX, create_nonpov_sm, create_sm, expected_validity_first_ack_duty,\n                expected_validity_first_nack_duty, get_state, mock_game_signatures,\n                mock_states::{\n                    TEST_BRIDGE_PROOF_TX, TEST_FULFILLMENT_TXID, acked_state, all_nackd_state,\n                    all_nackd_state_with, assigned_state, bridge_proof_posted_state_with,\n                    bridge_proof_timedout_state_with, claimed_state, contested_state_with,\n                    counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,\n                },\n                test_completed_signatures, test_deposit_params, test_graph_invalid_transition,\n                test_graph_sm_cfg, test_graph_sm_ctx, test_graph_summary, test_graph_transition,\n', 'validity-first new block 1'),
            ('        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());\n        let new_height = contest_height + proof_timelock + 1;\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_without_refuted_proof_state_with(\n                    contest_height,\n                    contest_height,\n                    None,\n                    Default::default(),\n                    BTreeMap::new(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_without_refuted_proof_state_with(\n                    new_height,\n                    contest_height,\n                    None,\n                    Default::default(),\n                    BTreeMap::new(),\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n', '        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());\n        let new_height = contest_height + proof_timelock + 1;\n\n        // The owner branch now unpacks the signatures to build any matured fixed NACKs\n        // before it reaches the proof-timeout check, so the state must carry a real\n        // signature vector rather than the empty default.\n        let sm = create_sm(counter_proof_posted_without_refuted_proof_state());\n        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_without_refuted_proof_state_with(\n                    contest_height,\n                    contest_height,\n                    None,\n                    signatures.clone(),\n                    BTreeMap::new(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_without_refuted_proof_state_with(\n                    new_height,\n                    contest_height,\n                    None,\n                    signatures,\n                    BTreeMap::new(),\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n', 'validity-first new block 2'),
            ('                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// Counterprover publishes ACK after nack timelock expires.\n    #[test]\n    fn counterproof_posted_nonpov_ack_viable_after_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let ctx = test_graph_sm_ctx();\n        let graph_summary = test_graph_summary();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock + 1;\n\n        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n            .expect("non-POV operator should map to watchtower slot");\n        let counterproofs_and_confs = BTreeMap::from([(\n            TEST_NONPOV_IDX,\n            CounterproofData {\n                txid: graph_summary.counterproofs[watchtower_slot].counterproof,\n                conf_height: counterproof_conf_height,\n                completed_signatures: test_completed_signatures(),\n            },\n        )]);\n\n        let game_graph = generate_game_graph(&cfg, &ctx, &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n        let sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())\n            .expect("Failed to unpack signatures");\n        let signed_counter_proof_ack_tx = game_graph.counterproofs[watchtower_slot]\n            .counterproof_ack\n            .clone()\n            .finalize(sigs.watchtowers[watchtower_slot].counterproof_ack);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_nonpov_sm,\n            get_state,\n            cfg,\n', '                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// Builds the confirmed-counterproof map for a single non-POV counterprover.\n    fn counterproofs_and_confs_for_nonpov(conf_height: u64) -> BTreeMap<u32, CounterproofData> {\n        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n            .expect("non-POV operator should map to watchtower slot");\n\n        BTreeMap::from([(\n            TEST_NONPOV_IDX,\n            CounterproofData {\n                txid: test_graph_summary().counterproofs[watchtower_slot].counterproof,\n                conf_height,\n                completed_signatures: test_completed_signatures(),\n            },\n        )])\n    }\n\n    /// Counterprover publishes ACK after nack timelock expires.\n    #[test]\n    fn counterproof_posted_nonpov_ack_viable_after_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock + 1;\n\n        let counterproofs_and_confs = counterproofs_and_confs_for_nonpov(counterproof_conf_height);\n\n        let sm = create_nonpov_sm(counter_proof_posted_state());\n        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n        // Validity-first emits the unsigned exact ACK template plus its N/N signatures; the\n        // executor finalizes it only once the RankLock positive unlock is resolved. The duty\n        // therefore no longer carries a finalized transaction. The bridge proof txid is the\n        // one the state machine reads out of `refuted_bridge_proof`, which\n        // `counter_proof_posted_state` populates with `TEST_BRIDGE_PROOF_TX`.\n        let expected_duty = expected_validity_first_ack_duty(\n            &cfg,\n            &sm,\n            &signatures,\n            TEST_BRIDGE_PROOF_TX.compute_txid(),\n        );\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_nonpov_sm,\n            get_state,\n            cfg,\n', 'validity-first new block 3'),
            ('                    new_height,\n                    contest_height,\n                    signatures,\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![GraphDuty::PublishCounterProofAck {\n                    signed_counter_proof_ack_tx,\n                }],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// ACK not allowed exactly at nack timelock boundary.\n    #[test]\n    fn counterproof_posted_nonpov_ack_not_viable_at_nack_timeout_boundary() {\n        let cfg = test_graph_sm_cfg();\n        let graph_summary = test_graph_summary();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock;\n        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n            .expect("non-POV operator should map to watchtower slot");\n\n        let counterproofs_and_confs = BTreeMap::from([(\n            TEST_NONPOV_IDX,\n            CounterproofData {\n                txid: graph_summary.counterproofs[watchtower_slot].counterproof,\n                conf_height: counterproof_conf_height,\n                completed_signatures: test_completed_signatures(),\n            },\n        )]);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_nonpov_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// ACK not allowed before nack timelock expires.\n    #[test]\n    fn counterproof_posted_nonpov_ack_not_viable_before_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let graph_summary = test_graph_summary();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock - 1;\n        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n            .expect("non-POV operator should map to watchtower slot");\n\n        let counterproofs_and_confs = BTreeMap::from([(\n            TEST_NONPOV_IDX,\n            CounterproofData {\n                txid: graph_summary.counterproofs[watchtower_slot].counterproof,\n                conf_height: counterproof_conf_height,\n                completed_signatures: test_completed_signatures(),\n            },\n        )]);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_nonpov_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// Graph owner does not publish ACK even after nack timelock expires.\n    #[test]\n    fn counterproof_posted_owner_no_ack_before_ack_timeout_even_after_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let graph_summary = test_graph_summary();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock + 1;\n        assert!(new_height <= contest_height + ack_timelock);\n\n        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n            .expect("non-POV operator should map to watchtower slot");\n        let counterproofs_and_confs = BTreeMap::from([(\n            TEST_NONPOV_IDX,\n            CounterproofData {\n                txid: graph_summary.counterproofs[watchtower_slot].counterproof,\n                conf_height: counterproof_conf_height,\n                completed_signatures: test_completed_signatures(),\n            },\n        )]);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    Default::default(),\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n', '                    new_height,\n                    contest_height,\n                    signatures,\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![expected_duty],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// Counterprover publishes ACK at the nack timelock boundary.\n    ///\n    /// This test previously asserted the opposite (`ack_not_viable_at_nack_timeout_boundary`).\n    /// That premise is obsolete under validity-first: the race is inverted, so the ACK is\n    /// immediate and the CSV gate now sits on the NACK instead. The assertion is therefore\n    /// replaced with the equivalent one for the new behaviour -- the ACK duty *is* emitted at\n    /// the boundary -- rather than dropped. The pre-maturity gate is still asserted, on the\n    /// NACK, by `counterproof_posted_owner_no_nack_before_nack_timeout` below.\n    #[test]\n    fn counterproof_posted_nonpov_ack_viable_at_nack_timeout_boundary() {\n        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock;\n\n        let counterproofs_and_confs = counterproofs_and_confs_for_nonpov(counterproof_conf_height);\n\n        let sm = create_nonpov_sm(counter_proof_posted_state());\n        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n        let expected_duty = expected_validity_first_ack_duty(\n            &cfg,\n            &sm,\n            &signatures,\n            TEST_BRIDGE_PROOF_TX.compute_txid(),\n        );\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_nonpov_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    signatures.clone(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    signatures,\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![expected_duty],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// The graph owner does not publish the fixed NACK before its CSV delay matures.\n    ///\n    /// This replaces `counterproof_posted_nonpov_ack_not_viable_before_nack_timeout`, whose\n    /// premise is obsolete: validity-first inverted the race, so the nack timelock no longer\n    /// gates the ACK. It gates the fixed NACK, and that is what is asserted here. The NACK\n    /// becomes emittable at `conf_height + nack_timelock - 1` (a CSV child may enter the very\n    /// next block), so `- 2` is the last strictly-immature height.\n    #[test]\n    fn counterproof_posted_owner_no_nack_before_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock - 2;\n\n        let counterproofs_and_confs = counterproofs_and_confs_for_nonpov(counterproof_conf_height);\n\n        let sm = create_sm(counter_proof_posted_state());\n        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    signatures.clone(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    signatures,\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n    /// Graph owner does not publish ACK even after nack timelock expires; it publishes the\n    /// fixed, CSV-gated NACK instead.\n    #[test]\n    fn counterproof_posted_owner_no_ack_before_ack_timeout_even_after_nack_timeout() {\n        let cfg = test_graph_sm_cfg();\n        let contest_height = LATER_BLOCK_HEIGHT;\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());\n        let counterproof_conf_height = contest_height + 1;\n        let new_height = counterproof_conf_height + nack_timelock + 1;\n        assert!(new_height <= contest_height + ack_timelock);\n\n        let counterproofs_and_confs = counterproofs_and_confs_for_nonpov(counterproof_conf_height);\n\n        let sm = create_sm(counter_proof_posted_state());\n        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n        let signatures = mock_game_signatures(&game_graph);\n        // The owner never ACKs its own graph. Under validity-first it does emit the fixed\n        // pre-signed NACK once the CSV delay has matured, so the duty list asserts exactly\n        // that one duty -- still proving no ACK duty is produced.\n        let expected_duty =\n            expected_validity_first_nack_duty(&cfg, &sm, &signatures, TEST_NONPOV_IDX);\n\n        test_transition::<GraphSM, _, _, _, _, _, _, _>(\n            create_sm,\n            get_state,\n            cfg,\n            GraphTransition {\n                from_state: counter_proof_posted_state_with(\n                    contest_height,\n                    contest_height,\n                    signatures.clone(),\n                    counterproofs_and_confs.clone(),\n                ),\n                event: GraphEvent::NewBlock(NewBlockEvent {\n                    block_height: new_height,\n                }),\n                expected_state: counter_proof_posted_state_with(\n                    new_height,\n                    contest_height,\n                    signatures,\n                    counterproofs_and_confs,\n                ),\n                expected_duties: vec![expected_duty],\n                expected_signals: vec![],\n            },\n        );\n    }\n\n', 'validity-first new block 4'),
        ],
        dry_run,
    )


def patch_bridge_sm_nack_tests(repo: Path, dry_run: bool) -> None:
    """Retarget bridge-sm tests that assert the old immediate-NACK polarity.

    Validity-first inverts the race: the ACK is immediate and the NACK is
    CSV-gated.  ``process_counterproof`` therefore emits no NACK duty at all
    (it moved to ``notify_new_block``/``retry``), and where a NACK duty is
    still emitted it is the fixed, exact, pre-signed
    ``PublishValidityFirstCounterProofNack`` rather than the old mutable one.

    Three consequences the fixtures must follow:

    * The state machine accepts only the exact pre-signed NACK, so
      ``nack_tx_for_slot`` returns the real template and the "an ACK must not be
      accepted as a NACK" test now feeds in the real ACK -- the strongest
      instance of its own premise, and the reason the separate ACK guard could
      be deleted from the transition.
    * Every ``CounterProofPosted`` retry-tick state now has its signatures
      unpacked, so the empty default no longer models a reachable state, and the
      expected NACK must be finalized with a signature drawn from the very
      vector the state carries.
    * A retry tick before the CSV delay matures emits no NACK.  The
      NACK-emitting fixtures are therefore matured explicitly, and a new
      immature case pins the gate itself.
    """

    # crates/bridge-sm/src/graph/tests/contested/process_counterproof.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/contested/process_counterproof.rs',
        [
            ('//! Unit tests for processing of the counterproof confirmation.\n\nuse std::collections::BTreeMap;\n\nuse bitcoin::Witness;\nuse strata_bridge_test_utils::bitcoin::generate_tx;\nuse strata_bridge_tx_graph::{\n    game_graph::GameConnectors,\n    transactions::prelude::{CounterproofNackData, CounterproofNackTx},\n};\n\nuse crate::{\n    graph::{\n        duties::GraphDuty,\n        errors::GSMError,\n        events::{CounterProofConfirmedEvent, GraphEvent},\n        machine::GraphSM,\n        state::{CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n            TEST_POV_IDX, TestGraphTxKind, create_nonpov_sm, dummy_proof_receipt, get_state,\n            mock_states::{\n                TEST_BRIDGE_PROOF_TX, TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY,\n                all_state_variants, bridge_proof_posted_state, contested_state,\n            },\n            test_completed_signatures, test_counterproof_tx, test_deposit_params,\n            test_graph_invalid_transition, test_graph_invalid_transition_with, test_graph_sm_cfg,\n            test_graph_sm_ctx, test_graph_transition,\n        },\n        watchtower::watchtower_slot_for_operator,\n    },\n    testing::test_transition,\n};\n\n', '//! Unit tests for processing of the counterproof confirmation.\n\nuse std::collections::BTreeMap;\n\nuse bitcoin::Witness;\nuse strata_bridge_test_utils::bitcoin::generate_tx;\n\nuse crate::{\n    graph::{\n        errors::GSMError,\n        events::{CounterProofConfirmedEvent, GraphEvent},\n        machine::{GraphSM, generate_game_graph},\n        state::{CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n            TEST_POV_IDX, TestGraphTxKind, create_nonpov_sm, dummy_proof_receipt,\n            expected_validity_first_ack_duty, get_state, mock_game_signatures,\n            mock_states::{\n                TEST_BRIDGE_PROOF_TX, TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY,\n                all_state_variants, bridge_proof_posted_state, bridge_proof_posted_state_with,\n                contested_state,\n            },\n            test_completed_signatures, test_counterproof_tx, test_deposit_params,\n            test_graph_invalid_transition, test_graph_invalid_transition_with, test_graph_sm_cfg,\n            test_graph_transition,\n        },\n        watchtower::watchtower_slot_for_operator,\n    },\n    testing::test_transition,\n};\n\n', 'no immediate NACK duty on counterproof 1'),
            ('        .expect("counterprover should have a watchtower slot");\n\n    CounterProofConfirmedEvent {\n        counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,\n        tx: test_counterproof_tx(),\n        counterprover_idx,\n    }\n}\n\n/// Builds the expected `PublishCounterProofNack` duty that the POV operator should emit.\nfn expected_nack_duty(counterprover_idx: u32) -> GraphDuty {\n    let cfg = test_graph_sm_cfg();\n    let ctx = test_graph_sm_ctx();\n    let deposit_params = test_deposit_params();\n    let setup_params = ctx.generate_setup_params(&cfg, &deposit_params);\n    let connectors = GameConnectors::new(\n        deposit_params.game_index,\n        &cfg.game_graph_params,\n        &setup_params,\n    );\n\n    let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, counterprover_idx)\n        .expect("counterprover should have a watchtower slot");\n\n    let counterproof_connector = connectors.counterproof[watchtower_slot];\n\n    let nack_data = CounterproofNackData {\n        counterproof_txid: TEST_GRAPH_SUMMARY.counterproofs[watchtower_slot].counterproof,\n    };\n    let counterproof_nack_tx = CounterproofNackTx::new(nack_data, counterproof_connector);\n\n    GraphDuty::PublishCounterProofNack {\n        deposit_idx: ctx.deposit_idx(),\n        counterprover_idx,\n        completed_signatures: test_completed_signatures(),\n        counterproof_nack_tx,\n    }\n}\n\n// ===== From Contested =====\n\n#[test]\n', '        .expect("counterprover should have a watchtower slot");\n\n    CounterProofConfirmedEvent {\n        counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,\n        tx: test_counterproof_tx(),\n        counterprover_idx,\n    }\n}\n\n// ===== From Contested =====\n\n#[test]\n', 'no immediate NACK duty on counterproof 2'),
            ('            refuted_bridge_proof: None,\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],\n        expected_signals: vec![],\n    });\n}\n\n#[test]\nfn event_accepted_from_contested_nonpov() {\n', '            refuted_bridge_proof: None,\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![],\n        expected_signals: vec![],\n    });\n}\n\n#[test]\nfn event_accepted_from_contested_nonpov() {\n', 'no immediate NACK duty on counterproof 3'),
            ('            refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],\n        expected_signals: vec![],\n    });\n}\n\n#[test]\nfn event_accepted_from_bridge_proof_posted_nonpov() {\n', '            refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![],\n        expected_signals: vec![],\n    });\n}\n\n#[test]\nfn event_accepted_from_bridge_proof_posted_nonpov() {\n', 'no immediate NACK duty on counterproof 4'),
            ('            txid: event.tx.compute_txid(),\n            conf_height: event.counterproof_block_height,\n            completed_signatures: test_completed_signatures(),\n        },\n    );\n\n    test_transition::<GraphSM, _, _, _, _, _, _, _>(\n        create_nonpov_sm,\n        get_state,\n        test_graph_sm_cfg(),\n        GraphTransition {\n            from_state: bridge_proof_posted_state(),\n            event: GraphEvent::CounterProofConfirmed(event.clone()),\n            expected_state: GraphState::CounterProofPosted {\n                last_block_height: LATER_BLOCK_HEIGHT,\n                graph_data: test_deposit_params(),\n                graph_summary: TEST_GRAPH_SUMMARY.clone(),\n                signatures: vec![],\n                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n                contest_block_height: LATER_BLOCK_HEIGHT,\n                refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),\n                counterproofs_and_confs: expected_counterproofs,\n                counterproof_nacks: BTreeMap::new(),\n                stake_spent: None,\n                payout_connector_spent: None,\n            },\n            expected_duties: vec![],\n            expected_signals: vec![],\n        },\n    );\n}\n\n// ===== From CounterProofPosted (accumulation) =====\n', '            txid: event.tx.compute_txid(),\n            conf_height: event.counterproof_block_height,\n            completed_signatures: test_completed_signatures(),\n        },\n    );\n\n    // The counterprover is this operator and the refuted bridge proof is already known, so\n    // validity-first resolves the immediate ACK on the very event that confirms the\n    // counterproof. (The old polarity emitted a NACK here, from the graph owner.)\n    let cfg = test_graph_sm_cfg();\n    let sm = create_nonpov_sm(bridge_proof_posted_state());\n    let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());\n    let signatures = mock_game_signatures(&game_graph);\n    let expected_duty = expected_validity_first_ack_duty(\n        &cfg,\n        &sm,\n        &signatures,\n        TEST_BRIDGE_PROOF_TX.compute_txid(),\n    );\n\n    test_transition::<GraphSM, _, _, _, _, _, _, _>(\n        create_nonpov_sm,\n        get_state,\n        cfg.clone(),\n        GraphTransition {\n            from_state: bridge_proof_posted_state_with(LATER_BLOCK_HEIGHT, signatures.clone()),\n            event: GraphEvent::CounterProofConfirmed(event.clone()),\n            expected_state: GraphState::CounterProofPosted {\n                last_block_height: LATER_BLOCK_HEIGHT,\n                graph_data: test_deposit_params(),\n                graph_summary: TEST_GRAPH_SUMMARY.clone(),\n                signatures,\n                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),\n                contest_block_height: LATER_BLOCK_HEIGHT,\n                refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),\n                counterproofs_and_confs: expected_counterproofs,\n                counterproof_nacks: BTreeMap::new(),\n                stake_spent: None,\n                payout_connector_spent: None,\n            },\n            expected_duties: vec![expected_duty],\n            expected_signals: vec![],\n        },\n    );\n}\n\n// ===== From CounterProofPosted (accumulation) =====\n', 'no immediate NACK duty on counterproof 5'),
            ('            refuted_bridge_proof: None,\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],\n        expected_signals: vec![],\n    });\n}\n\n// ===== Error Cases =====\n\n', '            refuted_bridge_proof: None,\n            counterproofs_and_confs: expected_counterproofs,\n            counterproof_nacks: BTreeMap::new(),\n            stake_spent: None,\n            payout_connector_spent: None,\n        },\n        expected_duties: vec![],\n        expected_signals: vec![],\n    });\n}\n\n// ===== Error Cases =====\n\n', 'no immediate NACK duty on counterproof 6'),
        ],
        dry_run,
    )

    # crates/bridge-sm/src/graph/tests/contested/process_counterproof_nackd.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/contested/process_counterproof_nackd.rs',
        [
            ('\nuse std::collections::BTreeMap;\n\nuse bitcoin::{OutPoint, Txid, hashes::Hash};\nuse strata_bridge_test_utils::{\n    bitcoin::{generate_spending_tx, generate_tx},\n    prelude::generate_txid,\n};\nuse strata_bridge_tx_graph::{\n    game_graph::GameGraphSummary, transactions::counterproof::CounterproofTx,\n};\n\nuse crate::{\n    graph::{\n        errors::GSMError,\n        events::{CounterProofNackConfirmedEvent, GraphEvent},\n        machine::GraphSM,\n        state::{AbortReason, CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n', '\nuse std::collections::BTreeMap;\n\nuse bitcoin::{Txid, hashes::Hash};\nuse strata_bridge_test_utils::{bitcoin::generate_tx, prelude::generate_txid};\nuse strata_bridge_tx_graph::game_graph::{GameGraph, GameGraphSummary};\n\nuse crate::{\n    graph::{\n        errors::GSMError,\n        events::{CounterProofNackConfirmedEvent, GraphEvent},\n        machine::{GraphSM, generate_game_graph},\n        state::{AbortReason, CounterproofData, GraphState},\n        tests::{\n            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,\n', 'exact fixed NACK in nackd tests 1'),
            ('                counter_proof_posted_state,\n            },\n            test_completed_signatures, test_deposit_params, test_graph_invalid_transition,\n            test_graph_sm_cfg, test_graph_transition,\n        },\n        watchtower::watchtower_slot_for_operator,\n    },\n', '                counter_proof_posted_state,\n            },\n            test_completed_signatures, test_deposit_params, test_graph_invalid_transition,\n            test_graph_sm_cfg, test_graph_sm_ctx, test_graph_transition,\n        },\n        watchtower::watchtower_slot_for_operator,\n    },\n', 'exact fixed NACK in nackd tests 2'),
            ('/// Creates a NACK tx that spends the ACK/NACK output of the counterproof at the given\n/// watchtower slot in the two-slot test summary.\nfn nack_tx_for_slot(slot: usize) -> bitcoin::Transaction {\n    let summary = test_graph_summary();\n    generate_spending_tx(\n        OutPoint {\n            txid: summary.counterproofs[slot].counterproof,\n            vout: CounterproofTx::ACK_NACK_VOUT,\n        },\n        &[],\n    )\n}\n\n', "/// Creates a NACK tx that spends the ACK/NACK output of the counterproof at the given\n/// watchtower slot in the two-slot test summary.\nfn nack_tx_for_slot(slot: usize) -> bitcoin::Transaction {\n    // Validity-first accepts only the exact fixed pre-signed NACK: the\n    // transition regenerates the game graph and compares\n    // counterproof_nack txids. An arbitrary transaction that merely spends\n    // the ACK/NACK outpoint is now correctly rejected, so the fixture must\n    // return the real template. The witness does not affect the txid, so the\n    // unsigned template is sufficient here.\n    test_game_graph().counterproofs[slot]\n        .counterproof_nack\n        .as_ref()\n        .clone()\n}\n\n/// The exact pre-signed counterproof ACK for the given watchtower slot.\nfn ack_tx_for_slot(slot: usize) -> bitcoin::Transaction {\n    test_game_graph().counterproofs[slot]\n        .counterproof_ack\n        .as_ref()\n        .clone()\n}\n\n/// The game graph these tests' state machines generate, built from the same config and\n/// context the state machines hold, so exact-txid comparisons agree.\nfn test_game_graph() -> GameGraph {\n    generate_game_graph(\n        &test_graph_sm_cfg(),\n        &test_graph_sm_ctx(),\n        &test_deposit_params(),\n    )\n}\n\n", 'exact fixed NACK in nackd tests 3'),
            ('    let mut summary = test_graph_summary();\n    let slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n        .expect("non-pov idx must have a watchtower slot");\n    let ack_looking_as_nack = nack_tx_for_slot(slot);\n    summary.counterproofs[slot].counterproof_ack = ack_looking_as_nack.compute_txid();\n\n    let counterproof_txid = summary.counterproofs[0].counterproof;\n', '    let mut summary = test_graph_summary();\n    let slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)\n        .expect("non-pov idx must have a watchtower slot");\n    // Validity-first accepts a NACK only if it is the exact pre-signed fixed NACK for the\n    // slot. Previously this test fed in an arbitrary spend of the ACK/NACK outpoint and\n    // relied on a separate "is this a known ACK?" guard. That guard is gone because the\n    // exact-txid check subsumes it, so the assertion is now made with the *real* ACK\n    // transaction for the same slot -- the strongest instance of the original premise.\n    let ack_looking_as_nack = ack_tx_for_slot(slot);\n    summary.counterproofs[slot].counterproof_ack = ack_looking_as_nack.compute_txid();\n\n    let counterproof_txid = summary.counterproofs[0].counterproof;\n', 'exact fixed NACK in nackd tests 4'),
        ],
        dry_run,
    )

    # crates/bridge-sm/src/graph/tests/handlers/process_retry_tick.rs
    patch(
        repo,
        'crates/bridge-sm/src/graph/tests/handlers/process_retry_tick.rs',
        [
            ('mod tests {\n    use std::sync::Arc;\n\n    use strata_bridge_primitives::types::OperatorIdx;\n    use strata_bridge_test_utils::bitcoin::generate_txid;\n    use strata_bridge_tx_graph::{\n        game_graph::GameConnectors,\n        transactions::prelude::{CounterproofNackData, CounterproofNackTx},\n    };\n    use strata_predicate::PredicateKey;\n\n    use crate::graph::{\n        duties::GraphDuty,\n        events::{GraphEvent, RetryTickEvent},\n        machine::{GraphSM, generate_game_graph},\n', 'mod tests {\n    use std::sync::Arc;\n\n    use musig2::secp256k1::schnorr::Signature;\n    use strata_bridge_primitives::types::OperatorIdx;\n    use strata_bridge_test_utils::bitcoin::generate_txid;\n    use strata_bridge_tx_graph::game_graph::GameConnectors;\n    use strata_predicate::PredicateKey;\n\n    use crate::graph::{\n        config::GraphSMCfg,\n        duties::GraphDuty,\n        events::{GraphEvent, RetryTickEvent},\n        machine::{GraphSM, generate_game_graph},\n', 'fixed exact NACK duty in retry tests 1'),
            ('        tests::{\n            FULFILLMENT_BLOCK_HEIGHT, GraphHandlerOutput, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,\n            TEST_ASSIGNEE, TEST_NONPOV_IDX, TEST_POV_IDX, create_nonpov_sm, create_sm,\n            dummy_proof_receipt, expected_potential_counterproof_duty, mock_game_signatures,\n            mock_states::{\n                assigned_state, bridge_proof_posted_state, bridge_proof_posted_state_with,\n                claimed_state, contested_state, counter_proof_posted_state,\n                counter_proof_posted_state_with, counter_proof_posted_state_with_signatures,\n                counter_proof_posted_without_refuted_proof_state, graph_signed_state,\n                terminal_states, test_graph_generated_state, test_nonce_context,\n            },\n            test_deposit_params, test_graph_sm_cfg, test_graph_summary,\n            test_nonpov_owned_handler_output, test_pov_owned_handler_output, test_recipient_desc,\n        },\n        watchtower::watchtower_slot_for_operator,\n    };\n\n    fn expected_pov_counterproof_idx(sm: &GraphSM) -> usize {\n', '        tests::{\n            FULFILLMENT_BLOCK_HEIGHT, GraphHandlerOutput, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,\n            TEST_ASSIGNEE, TEST_NONPOV_IDX, TEST_POV_IDX, create_nonpov_sm, create_sm,\n            dummy_proof_receipt, expected_potential_counterproof_duty,\n            expected_validity_first_ack_duty, expected_validity_first_nack_duty,\n            mock_game_signatures,\n            mock_states::{\n                assigned_state, bridge_proof_posted_state, bridge_proof_posted_state_with,\n                claimed_state, contested_state, counter_proof_posted_state,\n                counter_proof_posted_state_with, counter_proof_posted_state_with_signatures,\n                counter_proof_posted_without_refuted_proof_state,\n                counter_proof_posted_without_refuted_proof_state_with_signatures,\n                graph_signed_state, terminal_states, test_graph_generated_state,\n                test_nonce_context,\n            },\n            test_deposit_params, test_graph_sm_cfg, test_graph_summary,\n            test_nonpov_owned_handler_output, test_pov_owned_handler_output, test_recipient_desc,\n        },\n    };\n\n    fn expected_pov_counterproof_idx(sm: &GraphSM) -> usize {\n', 'fixed exact NACK duty in retry tests 2'),
            ("\n    // ===== CounterProofPosted retry tick tests =====\n    //\n    // Graph owner (PoV) — refuted_proof × NACK queue\n    //   None,    empty                  -> [bridge_proof]\n    //   None,    one pending            -> [bridge_proof, nack]\n    //   None,    multiple pending       -> [bridge_proof, nack×N]\n    //   None,    all already NACK'd     -> [bridge_proof]\n    //   Some(_), empty                  -> []\n", '\n    // ===== CounterProofPosted retry tick tests =====\n    //\n    // Under validity-first the NACK is a fixed, pre-signed transaction gated by the nack\n    // timelock, and the ACK is immediate. "Pending" below therefore means a confirmed\n    // counterproof whose CSV delay has matured.\n    //\n    // Graph owner (PoV) — refuted_proof × NACK queue\n    //   None,    empty                  -> [bridge_proof]\n    //   None,    one pending            -> [bridge_proof, nack]\n    //   None,    one immature           -> [bridge_proof]\n    //   None,    multiple pending       -> [bridge_proof, nack×N]\n    //   None,    all already NACK\'d     -> [bridge_proof]\n    //   Some(_), empty                  -> []\n', 'fixed exact NACK duty in retry tests 3'),
            ('    // Graph owner (non-PoV) — refuted_proof × proof valid? × PoV cp confirmed?\n    //   None, n/a,      no              -> []\n    //   None, n/a,      yes             -> []\n    //   Some, valid,    no              -> []\n    //   Some, valid,    yes             -> []\n    //   Some, invalid,  no              -> [counterproof]\n    //   Some, invalid,  yes             -> []\n\n    fn expected_bridge_proof_duty(\n        cfg: &Arc<crate::graph::config::GraphSMCfg>,\n', '    // Graph owner (non-PoV) — refuted_proof × proof valid? × PoV cp confirmed?\n    //   None, n/a,      no              -> []\n    //   None, n/a,      yes             -> []\n    //   Some, valid,    no              -> [counterproof]\n    //   Some, valid,    yes             -> [ack]\n    //   Some, invalid,  no              -> [counterproof]\n    //   Some, invalid,  yes             -> [ack]\n\n    fn expected_bridge_proof_duty(\n        cfg: &Arc<crate::graph::config::GraphSMCfg>,\n', 'fixed exact NACK duty in retry tests 4'),
            ('        )\n    }\n\n    fn expected_counterproof_nack_duty(\n        cfg: &Arc<crate::graph::config::GraphSMCfg>,\n        sm: &GraphSM,\n        state: &GraphState,\n        counterprover_idx: OperatorIdx,\n    ) -> GraphDuty {\n        let GraphState::CounterProofPosted {\n            graph_data,\n            counterproofs_and_confs,\n            ..\n        } = state\n        else {\n            panic!("expected CounterProofPosted state");\n        };\n\n        let setup_params = sm.context().generate_setup_params(cfg, graph_data);\n        let connectors =\n            GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);\n\n        let watchtower_slot = watchtower_slot_for_operator(\n            sm.context().operator_table().pov_idx(),\n            counterprover_idx,\n        )\n        .unwrap();\n\n        let data = counterproofs_and_confs.get(&counterprover_idx).unwrap();\n        let counterproof_connector = connectors.counterproof[watchtower_slot];\n        let nack_data = CounterproofNackData {\n            counterproof_txid: data.txid,\n        };\n        let counterproof_nack_tx = CounterproofNackTx::new(nack_data, counterproof_connector);\n\n        GraphDuty::PublishCounterProofNack {\n            deposit_idx: sm.context().deposit_idx(),\n            counterprover_idx,\n            completed_signatures: data.completed_signatures,\n            counterproof_nack_tx,\n        }\n    }\n\n    // ---- Graph owner is PoV operator ----\n\n    // (refuted_proof: None,    NACK queue: empty)               -> [bridge_proof]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_in_counter_proof_posted_for_pov_graph_when_no_refuted_proof()\n     {\n        let cfg = test_graph_sm_cfg();\n        let state = counter_proof_posted_without_refuted_proof_state();\n        let sm = create_sm(state.clone());\n        let expected_duty = expected_bridge_proof_duty(&cfg, &sm, &state);\n\n        test_pov_owned_handler_output(\n', '        )\n    }\n\n    /// The fixed, exact, pre-signed NACK the graph owner emits once the CSV delay matures.\n    ///\n    /// Validity-first replaced the mutable `PublishCounterProofNack` duty (built on the fly\n    /// from a connector) with a single pre-signed transaction, so the expectation must be\n    /// finalized with the signature drawn from the very signature vector the state under\n    /// test carries -- not a freshly mocked one.\n    fn expected_counterproof_nack_duty(\n        cfg: &Arc<GraphSMCfg>,\n        sm: &GraphSM,\n        state: &GraphState,\n        counterprover_idx: OperatorIdx,\n    ) -> GraphDuty {\n        let GraphState::CounterProofPosted { signatures, .. } = state else {\n            panic!("expected CounterProofPosted state");\n        };\n\n        expected_validity_first_nack_duty(cfg, sm, signatures, counterprover_idx)\n    }\n\n    /// The immediate ACK a counterproving watchtower re-emits on every retry tick while the\n    /// RankLock positive unlock is unresolved.\n    fn expected_ack_duty(cfg: &Arc<GraphSMCfg>, sm: &GraphSM, state: &GraphState) -> GraphDuty {\n        let GraphState::CounterProofPosted {\n            signatures,\n            refuted_bridge_proof: Some((bridge_proof_tx, _)),\n            ..\n        } = state\n        else {\n            panic!("expected CounterProofPosted state with refuted_bridge_proof present");\n        };\n\n        expected_validity_first_ack_duty(cfg, sm, signatures, bridge_proof_tx.compute_txid())\n    }\n\n    /// Rewinds every confirmed counterproof\'s `conf_height` so the fixed NACK\'s CSV delay has\n    /// matured at the state\'s `last_block_height`.\n    ///\n    /// Validity-first moved the timelock from the ACK to the NACK, so a retry tick before\n    /// maturity correctly emits no NACK. Tests asserting NACK emission must start from a\n    /// matured state; tests asserting a NACK is withheld for a *different* reason (already\n    /// nack\'d) are matured too, so the withholding is attributable to that reason alone.\n    fn with_matured_nack_timelock(mut state: GraphState, cfg: &GraphSMCfg) -> GraphState {\n        let GraphState::CounterProofPosted {\n            last_block_height,\n            counterproofs_and_confs,\n            ..\n        } = &mut state\n        else {\n            panic!("expected CounterProofPosted state");\n        };\n\n        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());\n        let conf_height = last_block_height.saturating_sub(nack_timelock);\n        for data in counterproofs_and_confs.values_mut() {\n            data.conf_height = conf_height;\n        }\n\n        state\n    }\n\n    // ---- Graph owner is PoV operator ----\n\n    /// The signature vector every `CounterProofPosted` retry-tick state must carry.\n    ///\n    /// Both retry branches now unpack the signatures (the owner builds matured fixed NACKs,\n    /// the counterprover builds the immediate ACK), so the empty default no longer models a\n    /// reachable state.\n    fn counter_proof_posted_signatures(cfg: &Arc<GraphSMCfg>, sm: &GraphSM) -> Vec<Signature> {\n        mock_game_signatures(&generate_game_graph(\n            cfg,\n            sm.context(),\n            &test_deposit_params(),\n        ))\n    }\n\n    // (refuted_proof: None,    NACK queue: empty)               -> [bridge_proof]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_in_counter_proof_posted_for_pov_graph_when_no_refuted_proof()\n     {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_without_refuted_proof_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = counter_proof_posted_without_refuted_proof_state_with_signatures(signatures);\n        let expected_duty = expected_bridge_proof_duty(&cfg, &sm, &state);\n\n        test_pov_owned_handler_output(\n', 'fixed exact NACK duty in retry tests 5'),
            ('        );\n    }\n\n    // (refuted_proof: None,    NACK queue: one pending)         -> [bridge_proof, nack]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_and_nack_in_counter_proof_posted_for_pov_graph() {\n        let cfg = test_graph_sm_cfg();\n        let state = counter_proof_posted_state_with(None, &[TEST_NONPOV_IDX], &[]);\n        let sm = create_sm(state.clone());\n        let expected_duties = vec![\n            expected_bridge_proof_duty(&cfg, &sm, &state),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n', '        );\n    }\n\n    // (refuted_proof: None,    NACK queue: one pending, matured)  -> [bridge_proof, nack]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_and_nack_in_counter_proof_posted_for_pov_graph() {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = with_matured_nack_timelock(\n            counter_proof_posted_state_with_signatures(None, &[TEST_NONPOV_IDX], &[], signatures),\n            &cfg,\n        );\n        let expected_duties = vec![\n            expected_bridge_proof_duty(&cfg, &sm, &state),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n', 'fixed exact NACK duty in retry tests 6'),
            ('        );\n    }\n\n    // (refuted_proof: None,    NACK queue: multiple pending)    -> [bridge_proof, nack×N]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_and_nacks_for_multiple_pending_counterproofs() {\n        const SECOND_NONPOV_IDX: OperatorIdx = 2;\n\n        let cfg = test_graph_sm_cfg();\n        let state =\n            counter_proof_posted_state_with(None, &[TEST_NONPOV_IDX, SECOND_NONPOV_IDX], &[]);\n        let sm = create_sm(state.clone());\n        let expected_duties = vec![\n            expected_bridge_proof_duty(&cfg, &sm, &state),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n', '        );\n    }\n\n    // (refuted_proof: None,    NACK queue: one pending, immature) -> [bridge_proof]\n    //\n    // The NACK is CSV-gated under validity-first, so before the delay matures the owner\n    // publishes nothing but the bridge proof. This is the counterpart to the test above and\n    // is what makes the maturity condition, rather than mere presence of a counterproof, the\n    // thing being asserted.\n    #[test]\n    fn test_retry_tick_withholds_nack_before_nack_timelock_matures() {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state =\n            counter_proof_posted_state_with_signatures(None, &[TEST_NONPOV_IDX], &[], signatures);\n        let expected_duty = expected_bridge_proof_duty(&cfg, &sm, &state);\n\n        test_pov_owned_handler_output(\n            cfg,\n            GraphHandlerOutput {\n                state,\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![expected_duty],\n            },\n        );\n    }\n\n    // (refuted_proof: None,    NACK queue: multiple pending)    -> [bridge_proof, nack×N]\n    #[test]\n    fn test_retry_tick_emits_bridge_proof_and_nacks_for_multiple_pending_counterproofs() {\n        const SECOND_NONPOV_IDX: OperatorIdx = 2;\n\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = with_matured_nack_timelock(\n            counter_proof_posted_state_with_signatures(\n                None,\n                &[TEST_NONPOV_IDX, SECOND_NONPOV_IDX],\n                &[],\n                signatures,\n            ),\n            &cfg,\n        );\n        let expected_duties = vec![\n            expected_bridge_proof_duty(&cfg, &sm, &state),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n', 'fixed exact NACK duty in retry tests 7'),
            ('    #[test]\n    fn test_retry_tick_emits_only_bridge_proof_when_counterproof_already_nacked() {\n        let cfg = test_graph_sm_cfg();\n        let state = counter_proof_posted_state_with(None, &[TEST_NONPOV_IDX], &[TEST_NONPOV_IDX]);\n        let sm = create_sm(state.clone());\n        let expected_duty = expected_bridge_proof_duty(&cfg, &sm, &state);\n\n        test_pov_owned_handler_output(\n', "    #[test]\n    fn test_retry_tick_emits_only_bridge_proof_when_counterproof_already_nacked() {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        // Matured, so the absent NACK is attributable to the already-nack'd entry alone.\n        let state = with_matured_nack_timelock(\n            counter_proof_posted_state_with_signatures(\n                None,\n                &[TEST_NONPOV_IDX],\n                &[TEST_NONPOV_IDX],\n                signatures,\n            ),\n            &cfg,\n        );\n        let expected_duty = expected_bridge_proof_duty(&cfg, &sm, &state);\n\n        test_pov_owned_handler_output(\n", 'fixed exact NACK duty in retry tests 8'),
            ('    // (refuted_proof: Some(_), NACK queue: empty)               -> []\n    #[test]\n    fn test_retry_tick_noop_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present() {\n        test_pov_owned_handler_output(\n            test_graph_sm_cfg(),\n            GraphHandlerOutput {\n                state: counter_proof_posted_state(),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n            },\n', '    // (refuted_proof: Some(_), NACK queue: empty)               -> []\n    #[test]\n    fn test_retry_tick_noop_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present() {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n\n        test_pov_owned_handler_output(\n            cfg,\n            GraphHandlerOutput {\n                state: counter_proof_posted_state_with_signatures(\n                    Some(dummy_proof_receipt()),\n                    &[],\n                    &[],\n                    signatures,\n                ),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n            },\n', 'fixed exact NACK duty in retry tests 9'),
            ('    fn test_retry_tick_emits_nack_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present()\n    {\n        let cfg = test_graph_sm_cfg();\n        let state =\n            counter_proof_posted_state_with(Some(dummy_proof_receipt()), &[TEST_NONPOV_IDX], &[]);\n        let sm = create_sm(state.clone());\n        let expected_duty = expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX);\n\n        test_pov_owned_handler_output(\n', '    fn test_retry_tick_emits_nack_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present()\n    {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = with_matured_nack_timelock(\n            counter_proof_posted_state_with_signatures(\n                Some(dummy_proof_receipt()),\n                &[TEST_NONPOV_IDX],\n                &[],\n                signatures,\n            ),\n            &cfg,\n        );\n        let expected_duty = expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX);\n\n        test_pov_owned_handler_output(\n', 'fixed exact NACK duty in retry tests 10'),
            ('        const SECOND_NONPOV_IDX: OperatorIdx = 2;\n\n        let cfg = test_graph_sm_cfg();\n        let state = counter_proof_posted_state_with(\n            Some(dummy_proof_receipt()),\n            &[TEST_NONPOV_IDX, SECOND_NONPOV_IDX],\n            &[],\n        );\n        let sm = create_sm(state.clone());\n        let expected_duties = vec![\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, SECOND_NONPOV_IDX),\n', '        const SECOND_NONPOV_IDX: OperatorIdx = 2;\n\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = with_matured_nack_timelock(\n            counter_proof_posted_state_with_signatures(\n                Some(dummy_proof_receipt()),\n                &[TEST_NONPOV_IDX, SECOND_NONPOV_IDX],\n                &[],\n                signatures,\n            ),\n            &cfg,\n        );\n        let expected_duties = vec![\n            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),\n            expected_counterproof_nack_duty(&cfg, &sm, &state, SECOND_NONPOV_IDX),\n', 'fixed exact NACK duty in retry tests 11'),
            ("    // (refuted_proof: Some(_), NACK queue: all already NACK'd)  -> []\n    #[test]\n    fn test_retry_tick_noop_when_counterproof_already_nacked_and_refuted_proof_present() {\n        test_pov_owned_handler_output(\n            test_graph_sm_cfg(),\n            GraphHandlerOutput {\n                state: counter_proof_posted_state_with(\n                    Some(dummy_proof_receipt()),\n                    &[TEST_NONPOV_IDX],\n                    &[TEST_NONPOV_IDX],\n                ),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n", "    // (refuted_proof: Some(_), NACK queue: all already NACK'd)  -> []\n    #[test]\n    fn test_retry_tick_noop_when_counterproof_already_nacked_and_refuted_proof_present() {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n\n        test_pov_owned_handler_output(\n            cfg.clone(),\n            GraphHandlerOutput {\n                state: with_matured_nack_timelock(\n                    counter_proof_posted_state_with_signatures(\n                        Some(dummy_proof_receipt()),\n                        &[TEST_NONPOV_IDX],\n                        &[TEST_NONPOV_IDX],\n                        signatures,\n                    ),\n                    &cfg,\n                ),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n", 'fixed exact NACK duty in retry tests 12'),
            ('        );\n    }\n\n    // (refuted_proof: Some, proof_valid?: valid, PoV cp confirmed: yes)    -> []\n    #[test]\n    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_proof_valid_and_local_counterproof_confirmed()\n     {\n        test_nonpov_owned_handler_output(\n            test_graph_sm_cfg(),\n            GraphHandlerOutput {\n                state: counter_proof_posted_state_with(\n                    Some(dummy_proof_receipt()),\n                    &[TEST_NONPOV_IDX],\n                    &[],\n                ),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n            },\n        );\n    }\n', '        );\n    }\n\n    // (refuted_proof: Some, proof_valid?: valid, PoV cp confirmed: yes)    -> [ack]\n    //\n    // Under the old polarity a confirmed local counterproof left the watchtower with nothing\n    // to retry; it waited out the nack timelock before ACKing. Validity-first makes the ACK\n    // immediate, so the retry tick re-emits the ACK resolution on every tick until the\n    // RankLock positive unlock resolves. The "no counterproof is re-posted" half of the old\n    // premise still holds: no PotentialCounterProof duty appears.\n    #[test]\n    fn test_retry_tick_emits_ack_in_counter_proof_posted_for_nonpov_graph_when_proof_valid_and_local_counterproof_confirmed()\n     {\n        let cfg = test_graph_sm_cfg();\n        let sm = create_nonpov_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = counter_proof_posted_state_with_signatures(\n            Some(dummy_proof_receipt()),\n            &[TEST_NONPOV_IDX],\n            &[],\n            signatures,\n        );\n        let expected_duty = expected_ack_duty(&cfg, &sm, &state);\n\n        test_nonpov_owned_handler_output(\n            cfg,\n            GraphHandlerOutput {\n                state,\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![expected_duty],\n            },\n        );\n    }\n', 'fixed exact NACK duty in retry tests 13'),
            ('        );\n    }\n\n    // (refuted_proof: Some, invalid,  PoV cp confirmed: yes)    -> []\n    #[test]\n    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_local_counterproof_confirmed()\n     {\n        let mut cfg = (*test_graph_sm_cfg()).clone();\n        cfg.bridge_proof_predicate = PredicateKey::never_accept();\n        let cfg = Arc::new(cfg);\n\n        test_nonpov_owned_handler_output(\n            cfg,\n            GraphHandlerOutput {\n                state: counter_proof_posted_state_with(\n                    Some(dummy_proof_receipt()),\n                    &[TEST_NONPOV_IDX],\n                    &[],\n                ),\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![],\n            },\n        );\n    }\n', '        );\n    }\n\n    // (refuted_proof: Some, invalid,  PoV cp confirmed: yes)    -> [ack]\n    //\n    // Same inversion as above; the GSM does not verify proofs, so the reject predicate does\n    // not change the duty.\n    #[test]\n    fn test_retry_tick_emits_ack_in_counter_proof_posted_for_nonpov_graph_when_local_counterproof_confirmed()\n     {\n        let mut cfg = (*test_graph_sm_cfg()).clone();\n        cfg.bridge_proof_predicate = PredicateKey::never_accept();\n        let cfg = Arc::new(cfg);\n\n        let sm = create_nonpov_sm(counter_proof_posted_state());\n        let signatures = counter_proof_posted_signatures(&cfg, &sm);\n        let state = counter_proof_posted_state_with_signatures(\n            Some(dummy_proof_receipt()),\n            &[TEST_NONPOV_IDX],\n            &[],\n            signatures,\n        );\n        let expected_duty = expected_ack_duty(&cfg, &sm, &state);\n\n        test_nonpov_owned_handler_output(\n            cfg,\n            GraphHandlerOutput {\n                state,\n                event: GraphEvent::RetryTick(RetryTickEvent),\n                expected_duties: vec![expected_duty],\n            },\n        );\n    }\n', 'fixed exact NACK duty in retry tests 14'),
        ],
        dry_run,
    )

def patch_base_logging_defect(repo: Path, dry_run: bool) -> None:
    """Base-tree defect, recorded as a delta distinct from validity-first.

    ``logging::init_from_env`` installs a global tracing dispatcher with no
    once-guard, so the *second* call in a process aborts the test binary with
    "a global default trace dispatcher has already been set".  There are 19
    call sites in the pinned base tree and none of them guard it, so any crate
    whose tests call it more than once per binary cannot run its suite.

    This is not caused by validity-first.  The attribution evidence is
    ``claim_payout``, which this installer never touches: it fails five tests
    with the identical panic at the pinned commit.  The blocked case here is
    STRATA-006, whose connector tests reach the same helper through
    ``assert_connector_is_spendable`` in ``crates/connectors/src/test_utils.rs``.

    The fix goes at the single definition site rather than the 19 call sites.
    ``init_logging_from_config`` is re-exported from the ``strata_logging``
    dependency and cannot be edited from here, so ``crates/common`` is the
    only place the guard can live.  The doc comment already states this
    helper is for tests and small helpers, and a repeat call previously
    panicked, so nothing can have depended on re-initialization.  Tests after
    the first in a binary now share the first test's service label, which is
    cosmetic.
    """

    rel = "crates/common/src/logging.rs"
    patch(repo, rel, [
        (
            "use std::env;\n",
            "use std::{env, sync::Once};\n",
            "import Once",
        ),
        (
            "pub fn init_from_env(service_base_name: &str) {\n"
            "    let service_label = get_service_label_from_env();\n"
            "\n"
            "    init_logging_from_config(LoggingInitConfig {",
            "pub fn init_from_env(service_base_name: &str) {\n"
            "    // The global tracing dispatcher can only be installed once per\n"
            "    // process; a second attempt panics. Test binaries call this from\n"
            "    // many tests, so the guard lives here rather than at each site.\n"
            "    static INIT: Once = Once::new();\n"
            "\n"
            "    INIT.call_once(|| {\n"
            "        let service_label = get_service_label_from_env();\n"
            "\n"
            "        init_logging_from_config(LoggingInitConfig {",
            "once-guard the global dispatcher",
        ),
        (
            "        extra_filter_directives: DEFAULT_EXTRA_FILTER_DIRECTIVES,\n"
            "    });\n"
            "}\n",
            "        extra_filter_directives: DEFAULT_EXTRA_FILTER_DIRECTIVES,\n"
            "        });\n"
            "    });\n"
            "}\n",
            "close the once-guard",
        ),
    ], dry_run)


def patch_p4_ack_witness_check(repo: Path, dry_run: bool) -> None:
    """Verify the ACK witness, not merely its txid.  See threat model P4.

    Applied after ``format_touched`` from a unified diff generated against
    an already-installed-and-formatted tree.  Generating it any other way
    does not apply: a diff taken against the pristine base carries the whole
    installer as context, and one taken from a long-lived scratch clone
    carries formatting the installer never produces.

    Under BIP141 a txid does not commit to the witness, so comparing
    ``event.counterproof_ack_txid`` could not establish that the ACK leaf was
    the leaf actually executed: a transaction carrying the expected txid but
    spending via another path was accepted as an ACK.  The ACK event did not
    even carry the transaction -- its sibling ``CounterProofConfirmedEvent``
    does -- so the check could not be written at the comparison site.

    This delta is applied from a shipped diff rather than from string anchors,
    unlike every other function here.  It touches six files and roughly 680
    lines, and hand-transcribing that many anchors is a worse risk than the
    loss of anchor-level granularity.  The check-then-apply contract is
    preserved: ``git apply --check`` is a real preflight and fails for the
    same reasons a missing anchor would.

    Also corrects a test-fixture defect the check exposed.  ``ack_preimage_hash``
    is sourced from ``wt_fault_pubkeys``, the field the ACK commitment was
    migrated into, and bridge-sm's ``TEST_FAULT_PUBKEYS`` filled it with
    ``generate_xonly_pubkey()``.  No preimage exists for a random 32-byte
    value, so those fixtures had never modelled a real ACK spend -- only a
    txid and a commitment nobody held the preimage for.  Test commitments are
    now ``sha256(preimage)``, rejection-sampled to a valid x-only encoding,
    matching what the tx-graph signer already did.
    """

    diff = HERE / "pending" / "p4-complete.diff"
    if not diff.is_file():
        raise SystemExit(f"missing P4 diff: {diff}")

    # --check is the preflight; it refuses on any context mismatch.
    run(repo, "git", "apply", "--check", "-p1", str(diff))
    if not dry_run:
        run(repo, "git", "apply", "-p1", str(diff))


def patch_base_p2p_address_collision(repo: Path, dry_run: bool) -> None:
    """Base-tree defect, recorded as a delta distinct from validity-first.

    The p2p test helpers give every ``Setup`` the same fixed libp2p memory
    addresses -- ``/memory/1``, ``/memory/2``, ... -- but libp2p's memory
    transport registry is process-global. A test therefore collides with an
    earlier test in the same binary whose listeners have not finished tearing
    down, and fails with "Failed to listen: No listener on the given port".

    Not caused by validity-first: the installer touches no other file under
    ``crates/p2p-service``, and the crate scores 3 passed / 1 failed on the
    patched tree against 2 passed / 2 failed on the pinned base (the patched
    tree already being better because patch_base_logging_defect repairs the
    other one). With this change the crate is 4 passed / 0 failed.

    The fix hands each ``Setup`` its own block of addresses from a process
    global counter, so tests cannot collide regardless of teardown timing.
    This is test-only code; no production path uses these helpers.
    """

    rel = "crates/p2p-service/src/tests/common.rs"
    patch(repo, rel, [
        (
            "use std::time::Duration;",
            "use std::{\n"
            "    sync::atomic::{AtomicU64, Ordering},\n"
            "    time::Duration,\n"
            "};",
            "import atomics for unique memory addresses",
        ),
        (
            "        let multiaddresses = (1..(keypairs.len() + 1) as u16)\n"
            "            .map(|idx| build_multiaddr!(Memory(idx)))\n"
            "            .collect::<Vec<_>>();",
            "        // libp2p's memory transport registry is process-global, so fixed\n"
            "        // addresses collide between tests in the same binary: a later test\n"
            "        // fails with \"No listener on the given port\" when an earlier test's\n"
            "        // listeners have not finished tearing down. Hand each Setup its own\n"
            "        // block of addresses instead.\n"
            "        static NEXT_MEMORY_PORT: AtomicU64 = AtomicU64::new(1);\n"
            "        let base = NEXT_MEMORY_PORT.fetch_add(keypairs.len() as u64, Ordering::Relaxed);\n"
            "        let multiaddresses = (0..keypairs.len() as u64)\n"
            "            .map(|offset| build_multiaddr!(Memory(base + offset)))\n"
            "            .collect::<Vec<_>>();",
            "unique memory addresses per test",
        ),
    ], dry_run)


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
            # Applied after formatting: this delta ships as a unified diff
            # generated against an already-installed-and-formatted tree, so
            # its context only matches once the anchor edits above have been
            # normalised.
            patch_p4_ack_witness_check(repo, False)
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("validity-first patch anchors verified" if args.check else "validity-first patch applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
