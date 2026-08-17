

from __future__ import annotations

"""Tier 0 cryptographic hardening, from the pre-audit cryptography review.

Two properties that a paid auditor would otherwise spend time rediscovering:
BN254's G2 subgroup membership is checked rather than assumed, and no garbling
entry point can be called without an explicit seed and profile.
"""

import pytest

# ---------------------------------------------------------------------------
# Tier 0 hardening, from the cryptography review.
# ---------------------------------------------------------------------------


def _off_subgroup_twist_point():
    """Solve the twist equation for a point that is on-curve but not in G2.

    Adding subgroup elements only ever yields subgroup elements, so the point
    has to come from the curve equation directly: pick x, take a square root
    of x^3 + B2, and keep it if [r]Q != O.
    """

    from ranklock.bn254_real import B2, CURVE_ORDER, FQ2, is_inf, is_on_curve, multiply

    for i in range(1, 200):
        x = FQ2((i, 1))
        y_squared = x * x * x + B2
        y = y_squared.sqrt()
        if y is None:
            continue
        point = (x, y, FQ2.one())
        if not is_on_curve(point, B2):
            continue
        if not is_inf(multiply(point, CURVE_ORDER, group="g2")):
            return point
    return None


def test_g2_rejects_on_curve_points_outside_the_order_r_subgroup():
    """BN254's twist has a cofactor, so on-curve is weaker than in-subgroup.

    The review demonstrated an on-curve twist point with [r]Q != O that
    decompress_g2 accepted and pairing_product then evaluated -- a non-trivial
    result on an input where the map is not even bilinear, so no soundness
    argument survives. No forgery was built; the check must exist regardless.
    """

    from ranklock.bn254_real import (
        B2,
        G1,
        G2,
        is_in_g2_subgroup,
        is_on_curve,
        pairing_product,
    )

    assert is_in_g2_subgroup(G2), "the generator must be in the subgroup"

    off_subgroup = _off_subgroup_twist_point()
    assert off_subgroup is not None, "expected to find an off-subgroup twist point"
    assert is_on_curve(off_subgroup, B2)
    assert not is_in_g2_subgroup(off_subgroup)

    with pytest.raises(ValueError, match="outside the order-r subgroup"):
        pairing_product([(G1, off_subgroup)])


def test_seed_and_profile_are_required_not_defaulted():
    """No caller may silently inherit predictable garbling material.

    The review demonstrated that two independent parties calling with the old
    defaults produced byte-identical Delta and labels, making every selector
    alternative openable. Both are now required keyword arguments; the weak
    80-prime DfbProfile default survives only for pinned fixtures and can no
    longer be reached by omission.
    """

    import inspect

    from ranklock.dfb_real import generate_program, generate_program_template

    for function in (generate_program, generate_program_template):
        parameters = inspect.signature(function).parameters
        assert parameters["seed"].default is inspect.Parameter.empty
        assert parameters["profile"].default is inspect.Parameter.empty
