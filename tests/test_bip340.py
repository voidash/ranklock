from pathlib import Path

import pytest

from ranklock.bip340 import (
    BIP340Error,
    public_key,
    sign,
    tapbranch_hash,
    tapleaf_hash,
    taproot_output_key,
    verify,
)
from ranklock.real_secp import N, P


def test_official_bip340_csv_vectors():
    vectors = Path(__file__).with_name("bip340-test-vectors.csv")
    rows = vectors.read_text().splitlines()[1:]
    for row in rows:
        # The official CSV contains no quoted commas in the vector fields used here.
        fields = row.split(",")
        index, secret_hex, pubkey_hex, aux_hex, message_hex, signature_hex, expected = fields[:7]
        pubkey = bytes.fromhex(pubkey_hex)
        message = bytes.fromhex(message_hex)
        signature = bytes.fromhex(signature_hex)
        assert verify(message, pubkey, signature) is (expected == "TRUE"), index
        if secret_hex:
            secret = int(secret_hex, 16)
            assert public_key(secret) == pubkey, index
            assert sign(message, secret, bytes.fromhex(aux_hex)) == signature, index


def test_signature_tampering_and_bounds_fail_closed():
    message = b"ranklock-bip340-test"
    pubkey = public_key(7)
    signature = sign(message, 7)
    assert verify(message, pubkey, signature)
    assert not verify(message + b"!", pubkey, signature)
    assert not verify(message, pubkey, signature[:-1] + bytes((signature[-1] ^ 1,)))
    assert not verify(message, P.to_bytes(32, "big"), signature)
    assert not verify(message, pubkey, signature[:32] + N.to_bytes(32, "big"))


def test_taproot_helpers_are_domain_separated_and_order_independent():
    left = tapleaf_hash(b"left")
    right = tapleaf_hash(b"right")
    assert left != right
    assert tapbranch_hash(left, right) == tapbranch_hash(right, left)
    output = taproot_output_key(public_key(13), tapbranch_hash(left, right))
    assert len(output) == 32
    with pytest.raises(BIP340Error):
        taproot_output_key(public_key(13), b"short")
