from dataclasses import replace

from ranklock.real_secp import (
    DleqProof,
    DeterministicScalars,
    G,
    N,
    SecpError,
    add,
    base_multiply,
    compress,
    decompress,
    ecdh_x,
    hash_point,
    multiply,
    prove_dleq,
    verify_dleq,
)


def test_group_encoding_ecdh_and_arbitrary_multiplication() -> None:
    a, b = 1234567, 9876543
    pa, pb = base_multiply(a), base_multiply(b)
    assert decompress(compress(pa)) == pa
    assert add(pa, pb) == base_multiply(a + b)
    assert multiply(pa, b) == multiply(pb, a)
    assert ecdh_x(a, pb) == ecdh_x(b, pa)
    assert multiply(pa, N) is None


def test_dleq_is_bound_and_tamper_resistant() -> None:
    witness = 424242
    h = hash_point(b"ranklock-test-h", 0)
    x = base_multiply(witness)
    y = multiply(h, witness)
    proof = prove_dleq(
        witness,
        G,
        x,
        h,
        y,
        domain=b"test",
        nonce_source=DeterministicScalars(b"nonce"),
    )
    assert DleqProof.parse(proof.encode()) == proof
    assert verify_dleq(proof, G, x, h, y, domain=b"test")
    assert not verify_dleq(replace(proof, response=(proof.response + 1) % N), G, x, h, y, domain=b"test")
    assert not verify_dleq(proof, G, x, h, y, domain=b"other")
    try:
        decompress(b"\x04" + bytes(32))
    except SecpError:
        pass
    else:  # pragma: no cover
        raise AssertionError("invalid point encoding accepted")
