from __future__ import annotations

"""Hashlocked validity-first Bitcoin connector with exact-message N/N presignatures.

A valid positive counterproof releases a 32-byte preimage.  The immediate ACK leaf requires
both that preimage and an N/N Schnorr signature bound to the exact ACK transaction.  The
relative-timeout NACK leaf requires only the pre-signed N/N signature after CSV maturity.
The released preimage is therefore not a reusable signing key and cannot authorize a junk
transaction.

The script/Taproot hashing and BIP340 signatures are real.  Transaction serialization is a
strict RankLock research format rather than Bitcoin consensus serialization; Bitcoin Core
regtest remains a separate gate.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from .babe_positive_lock import (
    BabePositiveLockError,
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    PositiveLock,
    unlock_positive_lock,
)
from .bip340 import (
    BIP340Error,
    lift_x,
    public_key,
    sign,
    tagged_hash,
    tapbranch_hash,
    tapleaf_hash,
    taproot_output_key,
    verify,
)


class PredicateHashlockError(RuntimeError):
    pass


OP_DROP = 0x75
OP_EQUAL = 0x87
OP_SHA256 = 0xA8
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKSEQUENCEVERIFY = 0xB2


def _push(data: bytes) -> bytes:
    data = bytes(data)
    if not 0 < len(data) <= 75:
        raise PredicateHashlockError("research script helper supports direct pushes of 1..75 bytes")
    return bytes((len(data),)) + data


def _scriptnum(value: int) -> bytes:
    if not 0 <= value < 2**31:
        raise PredicateHashlockError("relative delay is outside research scriptnum range")
    if value == 0:
        return b""
    output = bytearray()
    while value:
        output.append(value & 0xFF)
        value >>= 8
    if output[-1] & 0x80:
        output.append(0)
    return bytes(output)


def _nums_internal_key() -> bytes:
    """Derive an unspendable Taproot internal key, nothing-up-my-sleeve.

    This is deliberately NOT BIP341's example point
    ``lift_x(0x50929b74...03ac0)``, which is SHA256 of the uncompressed
    generator. It is a domain-separated hash-to-point over a fixed RankLock
    seed, tried against an incrementing counter until the candidate x
    coordinate lifts to a curve point.

    An adversarial review flagged the difference as a provenance defect, so
    to be explicit about why this is sound: the property required of an
    internal key is that nobody knows its discrete logarithm, not that it
    equals a particular published constant. Grinding the counter yields x
    coordinates, never discrete logs -- recovering one would mean solving
    ECDLP. The seed is a fixed literal in this file and the search is
    deterministic, so anyone can recompute the key and confirm no choice was
    made after seeing the result.

    A project-specific seed is used rather than the BIP341 example because the
    example point is shared by every project that copies it; a distinct point
    keeps RankLock outputs from being confused with unrelated ones. Both are
    equally unspendable.
    """

    seed = b"ranklock/validity-first/nums-internal-key/v1"
    for counter in range(2**32):
        candidate = int.from_bytes(sha256(seed + counter.to_bytes(4, "big")).digest(), "big")
        try:
            point = lift_x(candidate)
        except BIP340Error:
            continue
        if point is not None:
            return candidate.to_bytes(32, "big")
    raise PredicateHashlockError("failed to derive NUMS internal key")


NUMS_INTERNAL_KEY = _nums_internal_key()


def ack_leaf_script(n_of_n_pubkey: bytes, preimage_hash: bytes) -> bytes:
    n_of_n_pubkey, preimage_hash = bytes(n_of_n_pubkey), bytes(preimage_hash)
    if len(n_of_n_pubkey) != 32 or len(preimage_hash) != 32:
        raise PredicateHashlockError("ACK key and preimage hash must be 32 bytes")
    return (
        _push(n_of_n_pubkey)
        + bytes((OP_CHECKSIGVERIFY, OP_SHA256))
        + _push(preimage_hash)
        + bytes((OP_EQUAL,))
    )


def timeout_nack_leaf_script(n_of_n_pubkey: bytes, relative_delay: int) -> bytes:
    n_of_n_pubkey = bytes(n_of_n_pubkey)
    if len(n_of_n_pubkey) != 32:
        raise PredicateHashlockError("NACK key must be 32 bytes")
    delay = _scriptnum(relative_delay)
    return (
        _push(delay)
        + bytes((OP_CHECKSEQUENCEVERIFY, OP_DROP))
        + _push(n_of_n_pubkey)
        + bytes((OP_CHECKSIG,))
    )


@dataclass(frozen=True, slots=True)
class ValidityFirstHashlockConnector:
    n_of_n_pubkey: bytes
    preimage_hash: bytes
    relative_delay: int
    value_sat: int
    network: str = "regtest"
    schema: str = "ranklock-validity-first-hashlock-connector-v1"

    def __post_init__(self) -> None:
        if len(self.n_of_n_pubkey) != 32 or len(self.preimage_hash) != 32:
            raise PredicateHashlockError("connector key/hash must be 32 bytes")
        lift_x(int.from_bytes(self.n_of_n_pubkey, "big"))
        if not 1 <= self.relative_delay < 2**31:
            raise PredicateHashlockError("relative delay must be positive")
        if self.value_sat <= 0:
            raise PredicateHashlockError("connector value must be positive")

    @property
    def ack_script(self) -> bytes:
        return ack_leaf_script(self.n_of_n_pubkey, self.preimage_hash)

    @property
    def nack_script(self) -> bytes:
        return timeout_nack_leaf_script(self.n_of_n_pubkey, self.relative_delay)

    @property
    def ack_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.ack_script)

    @property
    def nack_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.nack_script)

    @property
    def merkle_root(self) -> bytes:
        return tapbranch_hash(self.ack_leaf_hash, self.nack_leaf_hash)

    @property
    def output_key(self) -> bytes:
        return taproot_output_key(NUMS_INTERNAL_KEY, self.merkle_root)

    @property
    def script_pubkey(self) -> bytes:
        return bytes((0x51, 0x20)) + self.output_key

    @property
    def digest(self) -> bytes:
        return sha256(
            b"ranklock/validity-first-hashlock-connector/v1\x00"
            + self.n_of_n_pubkey
            + self.preimage_hash
            + self.relative_delay.to_bytes(4, "big")
            + self.value_sat.to_bytes(8, "big")
            + len(self.network).to_bytes(2, "big")
            + self.network.encode()
            + self.merkle_root
        ).digest()


@dataclass(frozen=True, slots=True)
class TxOutput:
    value_sat: int
    script_pubkey: bytes

    def encode(self) -> bytes:
        if self.value_sat < 0 or len(self.script_pubkey) >= 2**16:
            raise PredicateHashlockError("invalid transaction output")
        return (
            self.value_sat.to_bytes(8, "big")
            + len(self.script_pubkey).to_bytes(2, "big")
            + bytes(self.script_pubkey)
        )


@dataclass(frozen=True, slots=True)
class BoundTransaction:
    kind: str
    prevout: bytes
    sequence: int
    outputs: tuple[TxOutput, ...]
    context_digest: bytes
    schema: str = "ranklock-bound-transaction-v1"

    def __post_init__(self) -> None:
        if self.kind not in {"ack", "nack"}:
            raise PredicateHashlockError("transaction kind must be ack or nack")
        if len(self.prevout) != 36 or len(self.context_digest) != 32:
            raise PredicateHashlockError("prevout/context length mismatch")
        if not 0 <= self.sequence < 2**32 or not self.outputs:
            raise PredicateHashlockError("invalid sequence or empty outputs")

    @property
    def encoding(self) -> bytes:
        encoded = bytearray(b"RANKLOCK-TX-V1\x00")
        encoded.extend(bytes((0 if self.kind == "ack" else 1,)))
        encoded.extend(self.prevout)
        encoded.extend(self.sequence.to_bytes(4, "big"))
        encoded.extend(self.context_digest)
        encoded.extend(len(self.outputs).to_bytes(2, "big"))
        for output in self.outputs:
            encoded.extend(output.encode())
        return bytes(encoded)

    @property
    def txid(self) -> bytes:
        return sha256(b"ranklock/txid/v1\x00" + self.encoding).digest()

    def sighash(self, connector: ValidityFirstHashlockConnector) -> bytes:
        leaf = connector.ack_leaf_hash if self.kind == "ack" else connector.nack_leaf_hash
        return tagged_hash(
            "TapSighash",
            b"ranklock-validity-first-sighash/v1\x00"
            + connector.digest
            + leaf
            + self.encoding,
        )


@dataclass(frozen=True, slots=True)
class HashlockPresignedGraph:
    connector: ValidityFirstHashlockConnector
    ack: BoundTransaction
    nack: BoundTransaction
    ack_signature: bytes
    nack_signature: bytes
    schema: str = "ranklock-hashlocked-presigned-graph-v1"

    def __post_init__(self) -> None:
        if self.ack.kind != "ack" or self.nack.kind != "nack":
            raise PredicateHashlockError("presigned graph transaction roles are inverted")
        if self.ack.prevout != self.nack.prevout:
            raise PredicateHashlockError("ACK and NACK must conflict on one connector outpoint")
        if self.ack.sequence != 0xFFFFFFFF:
            raise PredicateHashlockError("ACK must use the immediate path")
        if self.nack.sequence < self.connector.relative_delay:
            raise PredicateHashlockError("NACK sequence does not satisfy CSV")
        if not verify(
            self.ack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.ack_signature,
        ):
            raise PredicateHashlockError("invalid exact-message ACK presignature")
        if not verify(
            self.nack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.nack_signature,
        ):
            raise PredicateHashlockError("invalid exact-message NACK presignature")

    @property
    def digest(self) -> bytes:
        return sha256(
            b"ranklock/hashlocked-presigned-graph/v1\x00"
            + self.connector.digest
            + self.ack.txid
            + self.nack.txid
            + self.ack_signature
            + self.nack_signature
        ).digest()

    def verify_ack_witness(self, preimage: bytes) -> bool:
        return (
            len(preimage) == 32
            and sha256(bytes(preimage)).digest() == self.connector.preimage_hash
            and verify(
                self.ack.sighash(self.connector),
                self.connector.n_of_n_pubkey,
                self.ack_signature,
            )
        )

    def verify_timeout_nack(self, *, blocks_elapsed: int) -> bool:
        return (
            blocks_elapsed >= self.connector.relative_delay
            and verify(
                self.nack.sighash(self.connector),
                self.connector.n_of_n_pubkey,
                self.nack_signature,
            )
        )


def presign_hashlocked_graph(
    connector: ValidityFirstHashlockConnector,
    ack: BoundTransaction,
    nack: BoundTransaction,
    *,
    n_of_n_secret: int,
) -> HashlockPresignedGraph:
    if public_key(n_of_n_secret) != connector.n_of_n_pubkey:
        raise PredicateHashlockError("N/N secret does not match connector key")
    return HashlockPresignedGraph(
        connector=connector,
        ack=ack,
        nack=nack,
        ack_signature=sign(ack.sighash(connector), n_of_n_secret),
        nack_signature=sign(nack.sighash(connector), n_of_n_secret),
    )


def unlock_ack_preimage(
    graph: HashlockPresignedGraph,
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    proof: PositiveGroth16Proof,
    lock: PositiveLock,
    r_a_g1: bytes,
    *,
    session_context: bytes,
) -> bytes:
    try:
        preimage = unlock_positive_lock(
            vk,
            public_inputs,
            proof,
            lock,
            r_a_g1,
            session_context=session_context,
        )
    except BabePositiveLockError as exc:
        raise PredicateHashlockError(str(exc)) from exc
    if not graph.verify_ack_witness(preimage):
        raise PredicateHashlockError("unlocked payload does not satisfy the ACK hashlock")
    return preimage


@dataclass(frozen=True, slots=True)
class HashlockedValidityCost:
    embryo_bytes: int = 500 * 1024
    projective_input_bytes: int = 100_352
    activation_proof_allowance_bytes: int = 16 * 1024
    connector_manifest_bytes: int = 4 * 1024
    ceiling_bytes: int = 1 << 20
    schema: str = "ranklock-hashlocked-validity-cost-v1"

    @property
    def total_bytes(self) -> int:
        return (
            self.embryo_bytes
            + self.projective_input_bytes
            + self.activation_proof_allowance_bytes
            + self.connector_manifest_bytes
        )

    @property
    def margin_bytes(self) -> int:
        return self.ceiling_bytes - self.total_bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "embryo_bytes": self.embryo_bytes,
            "projective_input_bytes": self.projective_input_bytes,
            "activation_proof_allowance_bytes": self.activation_proof_allowance_bytes,
            "connector_manifest_bytes": self.connector_manifest_bytes,
            "total_bytes": self.total_bytes,
            "ceiling_bytes": self.ceiling_bytes,
            "margin_bytes": self.margin_bytes,
            "scope": "planning envelope; only connector/signatures are concretely serialized here",
        }
