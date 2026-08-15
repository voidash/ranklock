from __future__ import annotations

"""Canonical v0.25.2 acceptance-matrix case identifiers.

Sourced verbatim from the handoff's ``03_ACCEPTANCE_MATRIX.md``.  Every
evidence report that claims to qualify a phase of the matrix must cover
exactly the case IDs listed here -- no more, no fewer -- so a partial,
renamed or silently dropped case cannot slip through qualification.
"""

from typing import Final

CORE_CASE_IDS: Final[tuple[str, ...]] = tuple(f"CORE-{i:03d}" for i in range(1, 31))

# STRATA-001..009 are the clean-checkout/patch/build phase (provenance through
# the full workspace test suite).  STRATA-010..020 are the execution phase
# (ACK/NACK behavior against a live bridge + Core).  The split matters: the
# build phase can be qualified without a running Core node; the execution
# phase cannot.
STRATA_BUILD_CASE_IDS: Final[tuple[str, ...]] = tuple(f"STRATA-{i:03d}" for i in range(1, 10))
STRATA_E2E_CASE_IDS: Final[tuple[str, ...]] = tuple(f"STRATA-{i:03d}" for i in range(10, 21))
STRATA_CASE_IDS: Final[tuple[str, ...]] = STRATA_BUILD_CASE_IDS + STRATA_E2E_CASE_IDS

EVID_CASE_IDS: Final[tuple[str, ...]] = tuple(f"EVID-{i:03d}" for i in range(1, 10))

ALL_CASE_IDS: Final[tuple[str, ...]] = CORE_CASE_IDS + STRATA_CASE_IDS + EVID_CASE_IDS
