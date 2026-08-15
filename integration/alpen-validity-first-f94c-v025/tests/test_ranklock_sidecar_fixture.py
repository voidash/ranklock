from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "ranklock_sidecar_fixture.py"
spec = importlib.util.spec_from_file_location("fixture", MODULE_PATH)
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

TX_A = "11" * 32
TX_B = "22" * 32


def args(**changes):
    base = dict(
        deposit=1,
        owner=2,
        game=3,
        watchtower=4,
        seed=None,
    )
    base.update(changes)
    return argparse.Namespace(**base)


def test_commitment_is_xonly_compatible_and_exact():
    preimage, commitment, _ = fixture.derive_setup(args())
    assert len(preimage) == len(commitment) == 32
    assert fixture.sha256(preimage) == commitment
    assert fixture.valid_xonly(commitment)


def test_alternate_game_and_deposit_do_not_reuse_unlock():
    _, commitment_a, _ = fixture.derive_setup(args())
    _, commitment_game, _ = fixture.derive_setup(args(game=4))
    _, commitment_deposit, _ = fixture.derive_setup(args(deposit=2))
    assert len({commitment_a, commitment_game, commitment_deposit}) == 3


def test_setup_and_unlock_names_are_context_bound():
    assert fixture.setup_stem(2, 1, 3, 4) != fixture.setup_stem(2, 2, 3, 4)
    assert fixture.unlock_stem(TX_A, TX_B, "33" * 32) != fixture.unlock_stem(
        TX_A, TX_B, "44" * 32
    )


def test_unlock_modes_write_valid_wrong_and_malformed_files(tmp_path):
    setup_args = args(root=str(tmp_path))
    fixture.cmd_setup(setup_args)
    stem = fixture.setup_stem(2, 1, 3, 4)
    expected = (tmp_path / "fixture-secrets" / f"{stem}.preimage").read_bytes()

    for mode, expected_len in (("valid", 32), ("wrong", 32), ("malformed", 31)):
        unlock_args = args(
            root=str(tmp_path),
            bridge_txid=TX_A,
            counterproof_txid=TX_B,
            ack_txid="33" * 32,
            mode=mode,
        )
        fixture.cmd_unlock(unlock_args)
        path = tmp_path / "unlock" / f"{fixture.unlock_stem(TX_A, TX_B, '33' * 32)}.preimage"
        data = path.read_bytes()
        assert len(data) == expected_len
        if mode == "valid":
            assert data == expected
        elif mode == "wrong":
            assert data != expected and len(data) == len(expected)
