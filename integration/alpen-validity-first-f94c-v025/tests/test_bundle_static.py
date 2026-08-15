from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]


def load_installer():
    path = ROOT / "apply_validity_first.py"
    spec = importlib.util.spec_from_file_location("installer", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_installer_is_pinned_and_preflights_before_writing():
    installer = load_installer()
    assert installer.BASE_COMMIT == "f94c06d08ff29eee746f3e20bd63078d2949b304"
    source = (ROOT / "apply_validity_first.py").read_text()
    assert "apply(repo, True)\n            apply(repo, False)" in source
    assert "git\", \"diff\", \"--check" in source


def test_connector_has_positive_ack_and_csv_nack_leaves():
    source = (ROOT / "new_files/crates/connectors/src/validity_first_counterproof.rs").read_text()
    for marker in (
        "OP_CHECKSIGVERIFY",
        "OP_SHA256",
        "OP_EQUAL",
        "OP_CSV",
        "NackTimeout",
        "Ack {",
    ):
        assert marker in source
    assert "*UNSPENDABLE_PUBLIC_KEY" in source


def test_fixed_transactions_are_exact_message_presigned():
    ack = (ROOT / "new_files/crates/tx-graph/src/transactions/counterproof_ack.rs").read_text()
    nack = (ROOT / "new_files/crates/tx-graph/src/transactions/counterproof_nack.rs").read_text()
    assert "impl PresignedTx" in ack
    assert "impl PresignedTx" in nack
    assert "finalize(\n        self,\n        preimage: [u8; 32]" in ack
    assert "push_input" not in nack and "push_output" not in nack
    assert "ParentTxCombined" in nack


def test_state_machine_polarity_is_inverted():
    transition = (ROOT / "new_files/crates/bridge-sm/src/graph/transitions/counterproof.rs").read_text()
    installer = (ROOT / "apply_validity_first.py").read_text()
    assert "validate_counterproof_and_resolve_ack" in transition
    assert "PublishCounterProofNack" not in transition
    assert "PublishValidityFirstCounterProofNack" in installer
    assert "ResolveValidityFirstCounterProofAck" in installer
    assert "data.conf_height.saturating_add(nack_timelock)" in installer


def test_context_and_exact_txid_binding_are_present():
    sidecar = (ROOT / "ranklock_sidecar_fixture.py").read_text()
    executor = (ROOT / "new_files/crates/bridge-exec/src/graph/ranklock.rs").read_text()
    installer = (ROOT / "apply_validity_first.py").read_text()
    for marker in ("owner{}-deposit{}-game{}-watchtower{}", "bridge{}-counterproof{}-ack{}"):
        assert marker in executor
    assert "setup_stem" in sidecar and "unlock_stem" in sidecar
    assert "subgraph.counterproof_nack.as_ref().compute_txid()" in installer


def test_vsize_accounting_constants_and_formula():
    source = (ROOT / "apply_validity_first.py").read_text()
    assert "COUNTERPROOF_ACK_VSIZE: u64 = 211" in source
    assert "let weight: u64 = 94 * 4 + 135 + leaf_script_len" in source
    # delay <= 16: script 37 bytes; weight 548; ceil(weight/4) = 137
    assert (94 * 4 + 135 + 37 + 3) // 4 == 137
    # delay 144: minimally encoded sequence push is 3 bytes; script 39; vsize 138
    assert (94 * 4 + 135 + 39 + 3) // 4 == 138
