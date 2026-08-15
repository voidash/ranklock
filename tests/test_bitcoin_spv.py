from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.bitcoin_spv import (
    BitcoinSpvError,
    BitcoinSpvInclusionProof,
    block_hash,
    commitment_script,
    compact_target,
    header_satisfies_pow,
)
from ranklock.bitcoin_tx import OutPoint, Transaction, TxIn, TxOut, sha256d


def H(value: bytes) -> bytes:
    return sha256(value).digest()


def publication_transaction(commitment: bytes) -> Transaction:
    return Transaction(
        version=2,
        inputs=(
            TxIn(
                previous_output=OutPoint(H(b"funding transaction"), 0),
                script_sig=b"",
                sequence=0xFFFFFFFD,
            ),
        ),
        outputs=(
            TxOut(0, commitment_script(commitment)),
            TxOut(1_000, b"\x51"),
        ),
    )


def mine_header(merkle_root: bytes, *, bits: int = 0x207FFFFF) -> bytes:
    prefix = (
        (4).to_bytes(4, "little", signed=True)
        + bytes(32)
        + bytes(merkle_root)[::-1]
        + (1_800_000_000).to_bytes(4, "little")
        + int(bits).to_bytes(4, "little")
    )
    for nonce in range(100_000):
        header = prefix + nonce.to_bytes(4, "little")
        if header_satisfies_pow(header):
            return header
    raise AssertionError("regtest-like header did not mine")


def proof_fixture(commitment: bytes | None = None) -> BitcoinSpvInclusionProof:
    digest = H(b"commitment") if commitment is None else bytes(commitment)
    transaction = publication_transaction(digest)
    header = mine_header(transaction.txid)
    return BitcoinSpvInclusionProof(
        block_header=header,
        publication_transaction=transaction.serialize(),
        transaction_index=0,
        transaction_count=1,
        merkle_branch=(),
    )


def test_spv_proof_verifies_transaction_commitment_merkle_root_and_pow() -> None:
    commitment = H(b"commitment")
    proof = proof_fixture(commitment)
    assert proof.verify(commitment_digest=commitment)
    assert proof.block_hash == block_hash(proof.block_header)
    assert proof.merkle_root == publication_transaction(commitment).txid
    assert proof.digest != bytes(32)


def test_wrong_commitment_header_or_branch_fails_closed() -> None:
    commitment = H(b"commitment")
    proof = proof_fixture(commitment)
    assert not proof.verify(commitment_digest=H(b"substitution"))

    header = bytearray(proof.block_header)
    header[36] ^= 1
    assert not replace(proof, block_header=bytes(header)).verify(
        commitment_digest=commitment
    )

    # Two transactions require one sibling.  Omitting it is invalid.
    truncated = replace(proof, transaction_count=2)
    assert not truncated.verify(commitment_digest=commitment)


def test_compact_target_rejects_negative_zero_and_overflow() -> None:
    assert compact_target(0x207FFFFF) > 0
    for bits in (0, 0x20800001, 0x23000001):
        with pytest.raises(BitcoinSpvError):
            compact_target(bits)

class FakeCore:
    def __init__(
        self,
        proof: BitcoinSpvInclusionProof,
        *,
        genesis: bytes,
        height: int,
        confirmations: int = 6,
        reorg_after_check: bool = False,
    ) -> None:
        self.proof = proof
        self.genesis = bytes(genesis)
        self.height = int(height)
        self.confirmations = int(confirmations)
        self.reorg_after_check = bool(reorg_after_check)
        self.height_reads = 0

    def call(self, method: str, *params: object) -> object:
        if method == "getblockhash":
            height = int(params[0])
            if height == 0:
                return self.genesis.hex()
            assert height == self.height
            self.height_reads += 1
            if self.reorg_after_check and self.height_reads > 1:
                return H(b"replacement block").hex()
            return self.proof.block_hash.hex()
        if method == "getblockheader":
            assert str(params[0]) == self.proof.block_hash.hex()
            verbose = bool(params[1])
            if not verbose:
                return self.proof.block_header.hex()
            return {
                "hash": self.proof.block_hash.hex(),
                "height": self.height,
                "confirmations": self.confirmations,
                "merkleroot": self.proof.merkle_root.hex(),
            }
        if method == "getrawtransaction":
            assert str(params[0]) == self.proof.publication_txid.hex()
            assert bool(params[1])
            assert str(params[2]) == self.proof.block_hash.hex()
            return {
                "hex": self.proof.publication_transaction.hex(),
                "txid": self.proof.publication_txid.hex(),
                "blockhash": self.proof.block_hash.hex(),
                "confirmations": self.confirmations,
            }
        raise AssertionError(f"unexpected RPC method: {method}")


def test_spv_proof_is_bound_to_cores_active_chain_and_exact_bytes() -> None:
    from ranklock.bitcoin_spv import verify_spv_inclusion_with_core

    commitment = H(b"commitment")
    proof = proof_fixture(commitment)
    genesis = H(b"regtest genesis")
    observation = verify_spv_inclusion_with_core(
        FakeCore(proof, genesis=genesis, height=499),
        proof=proof,
        chain_genesis_hash=genesis,
        block_height=499,
        commitment_digest=commitment,
        minimum_confirmations=6,
    )
    assert observation.block_hash == proof.block_hash
    assert observation.publication_txid == proof.publication_txid
    assert observation.confirmations == 6


def test_spv_core_binding_rejects_wrong_chain_shallow_block_and_reorg() -> None:
    from ranklock.bitcoin_spv import BitcoinSpvError, verify_spv_inclusion_with_core

    commitment = H(b"commitment")
    proof = proof_fixture(commitment)
    genesis = H(b"regtest genesis")
    common = dict(
        proof=proof,
        chain_genesis_hash=genesis,
        block_height=499,
        commitment_digest=commitment,
        minimum_confirmations=6,
    )
    with pytest.raises(BitcoinSpvError, match="genesis"):
        verify_spv_inclusion_with_core(
            FakeCore(proof, genesis=H(b"other chain"), height=499), **common
        )
    with pytest.raises(BitcoinSpvError, match="sufficiently buried"):
        verify_spv_inclusion_with_core(
            FakeCore(proof, genesis=genesis, height=499, confirmations=5), **common
        )
    with pytest.raises(BitcoinSpvError, match="changed"):
        verify_spv_inclusion_with_core(
            FakeCore(
                proof,
                genesis=genesis,
                height=499,
                reorg_after_check=True,
            ),
            **common,
        )
