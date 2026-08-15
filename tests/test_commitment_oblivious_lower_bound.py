from __future__ import annotations

from ranklock.commitment_oblivious_lower_bound import (
    ReusableHeaderOracle,
    lower_bound_scope,
    recover_randomizer_base_from_two_updates,
    session_from_recovered_base,
)
from ranklock.kzg_we_conjunction import opening_statement_and_witness
from ranklock.kzg_we_model import pairing
from ranklock.ppe_normal_form import FormalKzgSrs


def test_two_public_header_updates_reveal_randomizer_base() -> None:
    srs = FormalKzgSrs(tau=1087)
    oracle = ReusableHeaderOracle(131, srs)
    recovered = recover_randomizer_base_from_two_updates(
        point_zero=17,
        header_zero=oracle.header(17),
        point_one=29,
        header_one=oracle.header(29),
    )
    assert recovered == srs.g2.scale(131)


def test_recovered_base_computes_the_witness_session_for_any_statement() -> None:
    srs = FormalKzgSrs(tau=1091)
    oracle = ReusableHeaderOracle(137, srs)
    recovered = recover_randomizer_base_from_two_updates(
        point_zero=31,
        header_zero=oracle.header(31),
        point_one=43,
        header_one=oracle.header(43),
    )
    statement, witness = opening_statement_and_witness((3, 7, 19, 23), 47, srs=srs)
    public_session = session_from_recovered_base(statement, recovered, srs=srs)
    witness_session = pairing(witness.opening, oracle.header(statement.point))
    assert public_session == witness_session
    scope = lower_bound_scope()
    assert scope["remaining_dynamic_commitment_problem"] is True
