from __future__ import annotations

"""Domain-separated unbiased field challenges from an external beacon.

The cryptographic model assumes the 32-byte beacon is unpredictable until all
objects named by ``transcript_digest`` are irrevocably committed.  A Bitcoin
implementation must additionally prove ordering, active-chain membership, and a
minimum burial depth; this module only performs deterministic challenge
extraction.
"""

import hashlib
from typing import Collection


class BeaconError(ValueError):
    pass


def derive_field_challenge(
    *,
    beacon: bytes,
    transcript_digest: bytes,
    label: bytes,
    modulus: int,
    forbidden: Collection[int] = (),
) -> int:
    beacon = bytes(beacon)
    transcript_digest = bytes(transcript_digest)
    label = bytes(label)
    if len(beacon) != 32 or len(transcript_digest) != 32:
        raise BeaconError("beacon and transcript digest must be 32 bytes")
    if not label or len(label) > 128:
        raise BeaconError("challenge label length outside bounds")
    if modulus <= 2 or modulus.bit_length() > 256:
        raise BeaconError("unsupported challenge field")
    forbidden_values = {int(value) % modulus for value in forbidden}
    sample_space = 1 << 256
    acceptance_limit = sample_space - sample_space % modulus
    for counter in range(1 << 32):
        digest = hashlib.sha256(
            b"ranklock/external-beacon/challenge/v1\x00"
            + len(label).to_bytes(2, "big")
            + label
            + transcript_digest
            + beacon
            + counter.to_bytes(4, "big")
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate >= acceptance_limit:
            continue
        value = candidate % modulus
        if value not in forbidden_values:
            return value
    raise BeaconError("challenge rejection loop exhausted")
