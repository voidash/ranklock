from dataclasses import replace

from ranklock.crt_bridge import (
    build_bound_crt_mul_witness,
    estimate_explicit_crt_bridge,
    estimate_free_shared_table_lower_bound,
    estimate_bounded_quotient_crt_bridge,
    estimate_bounded_quotient_free_shared_table_lower_bound,
    verify_bound_crt_mul_witness,
)


def test_bound_crt_witness_links_bytes_to_both_residue_traces() -> None:
    witness = build_bound_crt_mul_witness(2**190 + 17, 2**180 + 29)
    assert verify_bound_crt_mul_witness(witness)

    bad_residues = (witness.z.residues[0] ^ 1, witness.z.residues[1])
    assert not verify_bound_crt_mul_witness(
        replace(witness, z=replace(witness.z, residues=bad_residues))
    )

    bad_core = replace(
        witness.core,
        quotient=replace(
            witness.core.quotient,
            residues=(
                witness.core.quotient.residues[0] ^ 1,
                witness.core.quotient.residues[1],
            ),
        ),
    )
    assert not verify_bound_crt_mul_witness(replace(witness, core=bad_core))


def test_crt_schedule_distinguishes_executable_binding_from_missing_cross_pcs_link() -> None:
    explicit = estimate_explicit_crt_bridge(1)
    assert explicit.native_nonlinear_products == 2
    assert explicit.total_lookup_events == 94
    assert explicit.simple_row_equivalent == 96
    assert not explicit.cross_field_binding_cost_included
    assert explicit.document()["warning"] is not None

    lower = estimate_free_shared_table_lower_bound(1)
    assert lower.native_nonlinear_products == 2
    assert lower.total_lookup_events == 66
    assert lower.simple_row_equivalent == 68
    assert not lower.cross_field_binding_cost_included


def test_crt_bounded_quotient_inventory_is_smaller_but_still_unbound() -> None:
    owner = estimate_bounded_quotient_crt_bridge(1)
    assert owner.native_nonlinear_products == 2
    assert owner.total_lookup_events == 63
    assert owner.total_linear_equations == 20
    assert owner.simple_row_equivalent == 65
    assert owner.quotient_bits == 254
    assert not owner.cross_field_binding_cost_included

    lower = estimate_bounded_quotient_free_shared_table_lower_bound(1)
    assert lower.native_nonlinear_products == 2
    assert lower.total_lookup_events == 49
    assert lower.total_linear_equations == 12
    assert lower.simple_row_equivalent == 51
    assert not lower.cross_field_binding_cost_included
