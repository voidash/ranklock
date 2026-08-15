from __future__ import annotations

"""Bounded Bitcoin transaction-in-block proofs used by RankLock evidence.

This module verifies three local facts without trusting a JSON-RPC response:

* the publication transaction is canonically serialized and its txid is fixed;
* its txid is included in the block header's Merkle root at the claimed index;
* the 80-byte header satisfies its own compact proof-of-work target.

It intentionally does *not* decide whether the header belongs to the best chain.
A production verifier must additionally cross-check the exact header hash and
height with independently administered Bitcoin Core nodes/checkpoints.  Keeping
that boundary explicit prevents a self-consistent private fork from being
mistaken for canonical-chain evidence.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from .bitcoin_tx import BitcoinTxError, Transaction, sha256d


class BitcoinSpvError(ValueError):
    pass


_HEADER_BYTES = 80
_HASH_BYTES = 32
_MAX_MERKLE_DEPTH = 64
_MAX_TRANSACTION_COUNT = 1 << 32
_MAX_PUBLICATION_TRANSACTION_BYTES = 400_000
_PROOF_DOMAIN = b"ranklock/bitcoin-spv-inclusion-proof/v1\x00"
_CORE_BLOCK_OBSERVATION_DOMAIN = (
    b"ranklock/bitcoin-core-block-observation/v1\x00"
)
_CORE_SPV_OBSERVATION_DOMAIN = b"ranklock/bitcoin-core-spv-observation/v1\x00"
_COMMITMENT_TAG = b"RLMPCCM1"


def _hash32(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != _HASH_BYTES:
        raise BitcoinSpvError(f"{name} must be 32 bytes")
    return raw


def block_hash(header: bytes) -> bytes:
    raw = bytes(header)
    if len(raw) != _HEADER_BYTES:
        raise BitcoinSpvError("Bitcoin block header must be 80 bytes")
    return sha256d(raw)[::-1]


def header_merkle_root(header: bytes) -> bytes:
    raw = bytes(header)
    if len(raw) != _HEADER_BYTES:
        raise BitcoinSpvError("Bitcoin block header must be 80 bytes")
    return raw[36:68][::-1]


def compact_target(bits: int) -> int:
    """Decode Bitcoin's unsigned compact target with Core-compatible bounds."""

    value = int(bits)
    if not 0 <= value <= 0xFFFFFFFF:
        raise BitcoinSpvError("compact target does not fit u32")
    exponent = value >> 24
    mantissa = value & 0x007FFFFF
    negative = bool(value & 0x00800000)
    if negative or mantissa == 0:
        raise BitcoinSpvError("compact target is negative or zero")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        target = mantissa << (8 * (exponent - 3))
    # Match the uint256 overflow conditions used by Bitcoin's compact decoder.
    overflow = (
        exponent > 34
        or (mantissa > 0xFF and exponent > 33)
        or (mantissa > 0xFFFF and exponent > 32)
    )
    if overflow or target <= 0 or target >= 1 << 256:
        raise BitcoinSpvError("compact target overflows uint256")
    return target


def header_satisfies_pow(header: bytes) -> bool:
    raw = bytes(header)
    if len(raw) != _HEADER_BYTES:
        return False
    try:
        target = compact_target(int.from_bytes(raw[72:76], "little"))
    except BitcoinSpvError:
        return False
    # uint256 hashes are compared as little-endian integers in Bitcoin.
    return int.from_bytes(sha256d(raw), "little") <= target


def commitment_payload(commitment_digest: bytes) -> bytes:
    return _COMMITMENT_TAG + _hash32(commitment_digest, "commitment digest")


def commitment_script(commitment_digest: bytes) -> bytes:
    payload = commitment_payload(commitment_digest)
    # Forty bytes fits Bitcoin's canonical direct-push opcode range.
    return b"\x6a" + bytes((len(payload),)) + payload


def transaction_commits_to(transaction: Transaction, commitment_digest: bytes) -> bool:
    expected = commitment_script(commitment_digest)
    return sum(output.script_pubkey == expected for output in transaction.outputs) == 1


def _merkle_root_from_branch(
    *,
    txid: bytes,
    transaction_index: int,
    transaction_count: int,
    merkle_branch: tuple[bytes, ...],
) -> bytes:
    current = _hash32(txid, "transaction id")[::-1]
    index = int(transaction_index)
    count = int(transaction_count)
    if not 0 < count <= _MAX_TRANSACTION_COUNT:
        raise BitcoinSpvError("transaction count is invalid")
    if not 0 <= index < count:
        raise BitcoinSpvError("transaction index is outside block")
    if len(merkle_branch) > _MAX_MERKLE_DEPTH:
        raise BitcoinSpvError("Merkle branch exceeds depth limit")

    branch_index = 0
    while count > 1:
        if branch_index >= len(merkle_branch):
            raise BitcoinSpvError("Merkle branch is truncated")
        sibling = _hash32(merkle_branch[branch_index], "Merkle sibling")[::-1]
        branch_index += 1
        sibling_index = index ^ 1
        if sibling_index >= count and sibling != current:
            raise BitcoinSpvError("odd Merkle level must duplicate the final node")
        if index & 1:
            current = sha256d(sibling + current)
        else:
            current = sha256d(current + sibling)
        index //= 2
        count = (count + 1) // 2

    if branch_index != len(merkle_branch):
        raise BitcoinSpvError("Merkle branch has trailing nodes")
    return current[::-1]


class BitcoinCoreSpvReader(Protocol):
    def call(self, method: str, *params: object) -> object: ...


@dataclass(frozen=True, slots=True)
class BitcoinCoreBlockObservation:
    chain_genesis_hash: bytes
    block_hash: bytes
    block_height: int
    confirmations: int
    schema: str = "ranklock-bitcoin-core-block-observation-v1"

    def __post_init__(self) -> None:
        _hash32(self.chain_genesis_hash, "chain genesis hash")
        _hash32(self.block_hash, "block hash")
        if not 0 <= int(self.block_height) < 2**64:
            raise BitcoinSpvError("block height is invalid")
        if not 1 <= int(self.confirmations) < 2**64:
            raise BitcoinSpvError("confirmation depth is invalid")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.chain_genesis_hash)
            + bytes(self.block_hash)
            + int(self.block_height).to_bytes(8, "big")
            + int(self.confirmations).to_bytes(8, "big")
        )

    @property
    def digest(self) -> bytes:
        return sha256(
            _CORE_BLOCK_OBSERVATION_DOMAIN + self.canonical_bytes
        ).digest()


@dataclass(frozen=True, slots=True)
class BitcoinCoreSpvObservation:
    chain_genesis_hash: bytes
    block_hash: bytes
    block_height: int
    confirmations: int
    publication_txid: bytes
    schema: str = "ranklock-bitcoin-core-spv-observation-v1"

    def __post_init__(self) -> None:
        _hash32(self.chain_genesis_hash, "chain genesis hash")
        _hash32(self.block_hash, "block hash")
        _hash32(self.publication_txid, "publication transaction id")
        if not 0 <= int(self.block_height) < 2**64:
            raise BitcoinSpvError("block height is invalid")
        if not 1 <= int(self.confirmations) < 2**64:
            raise BitcoinSpvError("confirmation depth is invalid")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.chain_genesis_hash)
            + bytes(self.block_hash)
            + int(self.block_height).to_bytes(8, "big")
            + int(self.confirmations).to_bytes(8, "big")
            + bytes(self.publication_txid)
        )

    @property
    def digest(self) -> bytes:
        return sha256(
            _CORE_SPV_OBSERVATION_DOMAIN + self.canonical_bytes
        ).digest()


def _rpc_hash(value: object, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise BitcoinSpvError(f"Bitcoin Core returned malformed {name}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise BitcoinSpvError(f"Bitcoin Core returned non-hexadecimal {name}") from exc


def verify_active_chain_block(
    reader: BitcoinCoreSpvReader,
    *,
    chain_genesis_hash: bytes,
    block_height: int,
    expected_block_hash: bytes,
    minimum_confirmations: int,
) -> BitcoinCoreBlockObservation:
    """Verify one exact block is stable in Core's active chain."""

    expected_genesis = _hash32(chain_genesis_hash, "chain genesis hash")
    expected_hash = _hash32(expected_block_hash, "expected block hash")
    height = int(block_height)
    depth = int(minimum_confirmations)
    if not 0 <= height < 2**64:
        raise BitcoinSpvError("block height is invalid")
    if not 1 <= depth < 2**31:
        raise BitcoinSpvError("minimum confirmation depth is invalid")
    genesis = _rpc_hash(reader.call("getblockhash", 0), "genesis block hash")
    if genesis != expected_genesis:
        raise BitcoinSpvError("Bitcoin Core chain genesis differs")
    active_hash = _rpc_hash(reader.call("getblockhash", height), "active-chain block hash")
    if active_hash != expected_hash:
        raise BitcoinSpvError("expected block is not active at the signed height")
    verbose = reader.call("getblockheader", active_hash.hex(), True)
    if not isinstance(verbose, dict):
        raise BitcoinSpvError("Bitcoin Core returned malformed verbose block header")
    try:
        observed_height = int(verbose["height"])
        confirmations = int(verbose["confirmations"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BitcoinSpvError("Bitcoin Core verbose block header is incomplete") from exc
    if observed_height != height:
        raise BitcoinSpvError("Bitcoin Core block height differs")
    if confirmations < depth:
        raise BitcoinSpvError("block is not sufficiently buried in the active chain")
    if "hash" in verbose and _rpc_hash(verbose["hash"], "header hash") != expected_hash:
        raise BitcoinSpvError("Bitcoin Core verbose header hash differs")
    after = _rpc_hash(reader.call("getblockhash", height), "post-check active-chain block hash")
    if after != expected_hash:
        raise BitcoinSpvError("Bitcoin active chain changed during block verification")
    return BitcoinCoreBlockObservation(
        chain_genesis_hash=expected_genesis,
        block_hash=expected_hash,
        block_height=height,
        confirmations=confirmations,
    )


def verify_spv_inclusion_with_core(
    reader: BitcoinCoreSpvReader,
    *,
    proof: "BitcoinSpvInclusionProof",
    chain_genesis_hash: bytes,
    block_height: int,
    commitment_digest: bytes,
    minimum_confirmations: int,
) -> BitcoinCoreSpvObservation:
    """Bind a local SPV proof to Bitcoin Core's active best chain.

    The active-chain block hash is read both before and after the transaction and
    header checks.  Any reorg/race or byte-level disagreement fails closed.
    """

    expected_genesis = _hash32(chain_genesis_hash, "chain genesis hash")
    height = int(block_height)
    depth = int(minimum_confirmations)
    if not 0 <= height < 2**64:
        raise BitcoinSpvError("block height is invalid")
    if not 1 <= depth < 2**31:
        raise BitcoinSpvError("minimum confirmation depth is invalid")
    if not proof.verify(commitment_digest=commitment_digest):
        raise BitcoinSpvError("local SPV inclusion proof failed verification")

    genesis = _rpc_hash(reader.call("getblockhash", 0), "genesis block hash")
    if genesis != expected_genesis:
        raise BitcoinSpvError("Bitcoin Core chain genesis differs from ceremony anchor")

    active_hash = _rpc_hash(reader.call("getblockhash", height), "active-chain block hash")
    if active_hash != proof.block_hash:
        raise BitcoinSpvError("SPV header is not the active-chain block at the signed height")
    block_hash_hex = active_hash.hex()

    raw_header = reader.call("getblockheader", block_hash_hex, False)
    if not isinstance(raw_header, str):
        raise BitcoinSpvError("Bitcoin Core returned malformed raw block header")
    try:
        core_header = bytes.fromhex(raw_header)
    except ValueError as exc:
        raise BitcoinSpvError("Bitcoin Core raw block header is not hexadecimal") from exc
    if core_header != proof.block_header:
        raise BitcoinSpvError("Bitcoin Core block header differs byte-for-byte from SPV proof")

    verbose_header = reader.call("getblockheader", block_hash_hex, True)
    if not isinstance(verbose_header, dict):
        raise BitcoinSpvError("Bitcoin Core returned malformed verbose block header")
    try:
        header_height = int(verbose_header["height"])
        header_confirmations = int(verbose_header["confirmations"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BitcoinSpvError("Bitcoin Core verbose block header is incomplete") from exc
    if header_height != height:
        raise BitcoinSpvError("Bitcoin Core block height differs from ceremony anchor")
    if header_confirmations < depth:
        raise BitcoinSpvError("commitment publication block is not sufficiently buried")
    if "hash" in verbose_header and _rpc_hash(verbose_header["hash"], "header hash") != active_hash:
        raise BitcoinSpvError("Bitcoin Core verbose header hash differs")
    if "merkleroot" in verbose_header and _rpc_hash(
        verbose_header["merkleroot"], "Merkle root"
    ) != header_merkle_root(proof.block_header):
        raise BitcoinSpvError("Bitcoin Core Merkle root differs from SPV proof")

    txid_hex = proof.publication_txid.hex()
    transaction = reader.call("getrawtransaction", txid_hex, True, block_hash_hex)
    if not isinstance(transaction, dict):
        raise BitcoinSpvError("Bitcoin Core returned malformed publication transaction")
    try:
        core_transaction = bytes.fromhex(str(transaction["hex"]))
        tx_confirmations = int(transaction["confirmations"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BitcoinSpvError("Bitcoin Core publication transaction result is incomplete") from exc
    if core_transaction != proof.publication_transaction:
        raise BitcoinSpvError("Bitcoin Core publication transaction differs byte-for-byte")
    if _rpc_hash(transaction.get("txid"), "publication txid") != proof.publication_txid:
        raise BitcoinSpvError("Bitcoin Core publication txid differs from SPV proof")
    if _rpc_hash(transaction.get("blockhash"), "publication block hash") != active_hash:
        raise BitcoinSpvError("Bitcoin Core reports another publication block")
    if tx_confirmations != header_confirmations or tx_confirmations < depth:
        raise BitcoinSpvError("Bitcoin Core confirmation views changed during anchor check")

    active_hash_after = _rpc_hash(
        reader.call("getblockhash", height), "post-check active-chain block hash"
    )
    if active_hash_after != active_hash:
        raise BitcoinSpvError("Bitcoin active chain changed during anchor verification")

    return BitcoinCoreSpvObservation(
        chain_genesis_hash=expected_genesis,
        block_hash=active_hash,
        block_height=height,
        confirmations=header_confirmations,
        publication_txid=proof.publication_txid,
    )


@dataclass(frozen=True, slots=True)
class BitcoinSpvInclusionProof:
    block_header: bytes
    publication_transaction: bytes
    transaction_index: int
    transaction_count: int
    merkle_branch: tuple[bytes, ...]
    schema: str = "ranklock-bitcoin-spv-inclusion-proof-v1"

    def __post_init__(self) -> None:
        header = bytes(self.block_header)
        transaction = bytes(self.publication_transaction)
        branch = tuple(bytes(item) for item in self.merkle_branch)
        if len(header) != _HEADER_BYTES:
            raise BitcoinSpvError("Bitcoin block header must be 80 bytes")
        if not 0 < len(transaction) <= _MAX_PUBLICATION_TRANSACTION_BYTES:
            raise BitcoinSpvError("publication transaction size is invalid")
        if not 0 < int(self.transaction_count) <= _MAX_TRANSACTION_COUNT:
            raise BitcoinSpvError("transaction count is invalid")
        if not 0 <= int(self.transaction_index) < int(self.transaction_count):
            raise BitcoinSpvError("transaction index is outside block")
        if len(branch) > _MAX_MERKLE_DEPTH:
            raise BitcoinSpvError("Merkle branch exceeds depth limit")
        for item in branch:
            _hash32(item, "Merkle sibling")
        object.__setattr__(self, "block_header", header)
        object.__setattr__(self, "publication_transaction", transaction)
        object.__setattr__(self, "merkle_branch", branch)

    @property
    def transaction(self) -> Transaction:
        try:
            return Transaction.parse(self.publication_transaction)
        except BitcoinTxError as exc:
            raise BitcoinSpvError("publication transaction is not canonical") from exc

    @property
    def publication_txid(self) -> bytes:
        return self.transaction.txid

    @property
    def block_hash(self) -> bytes:
        return block_hash(self.block_header)

    @property
    def merkle_root(self) -> bytes:
        return _merkle_root_from_branch(
            txid=self.publication_txid,
            transaction_index=self.transaction_index,
            transaction_count=self.transaction_count,
            merkle_branch=self.merkle_branch,
        )

    @property
    def canonical_bytes(self) -> bytes:
        transaction = bytes(self.publication_transaction)
        return (
            bytes(self.block_header)
            + int(self.transaction_index).to_bytes(4, "big")
            + int(self.transaction_count).to_bytes(4, "big")
            + len(self.merkle_branch).to_bytes(1, "big")
            + b"".join(self.merkle_branch)
            + len(transaction).to_bytes(4, "big")
            + transaction
        )

    @property
    def digest(self) -> bytes:
        return sha256(_PROOF_DOMAIN + self.canonical_bytes).digest()

    def verify(self, *, commitment_digest: bytes) -> bool:
        try:
            transaction = self.transaction
            return bool(
                header_satisfies_pow(self.block_header)
                and self.merkle_root == header_merkle_root(self.block_header)
                and transaction_commits_to(transaction, commitment_digest)
            )
        except (BitcoinSpvError, BitcoinTxError):
            return False
