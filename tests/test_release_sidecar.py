from __future__ import annotations

from hashlib import sha256
import os

import numpy as np
import pytest

from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bip340 import public_key
from ranklock.bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    WitnessItemRule,
    witness_control_hash,
    witness_script_hash,
)
from ranklock.bn254_real import FIELD_MODULUS, G1, affine, multiply
from ranklock.bounded_mpc_embryo import slot_descriptor_from_artifact
from ranklock.committee_authorization import (
    ParticipantSlotSecrets,
    dealer_split_fixture,
    issue_committee_request,
)
from ranklock.dfb_real import CoordinateInputEncoding
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.release_sidecar import (
    BitcoinCoreRpcConfig,
    ParticipantReleaseSidecar,
    ReleaseSidecarError,
    atomic_write_once,
    read_secret_file_secure,
    require_secret_file_permissions,
)
from ranklock.rollback_witness import SqliteRollbackWitness


def _compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    raise AssertionError("test vector is unexpectedly large")


def _witness_for_point(point):
    coordinates = affine(point)
    assert coordinates is not None
    input_bits = FIELD_MODULUS.bit_length()
    rules = []
    selected = []
    for coordinate, value in enumerate(int(item.n) for item in coordinates):
        for bit in range(input_bits):
            prefix = bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"ranklock-zero/" + prefix
            one = b"ranklock-one/" + prefix
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate,
                    bit=bit,
                    zero_item=zero,
                    one_item=one,
                )
            )
            selected.append(one if (value >> bit) & 1 else zero)
    tapscript = b"\x51"
    control = b"\xc0" + b"I" * 32
    return input_bits, tuple(rules), tuple(selected), tapscript, control


def _raw_tx(witness_items: tuple[bytes, ...]) -> bytes:
    script = b"\x51\x20" + b"P" * 32
    witness = _compact(len(witness_items)) + b"".join(
        _compact(len(item)) + item for item in witness_items
    )
    return (
        (3).to_bytes(4, "little")
        + b"\x00\x01"
        + b"\x01"
        + bytes(range(32))
        + (2).to_bytes(4, "little")
        + b"\x00"
        + bytes.fromhex("fdffffff")
        + b"\x01"
        + (90_000).to_bytes(8, "little")
        + bytes((len(script),))
        + script
        + witness
        + bytes(4)
    )


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(), labels=words.copy(), delta=offset + 0x123456789ABCDEF
    )


def _fixture(tmp_path):
    point = multiply(G1, 777, group="g1")
    input_bits, rules, selected, tapscript, control = _witness_for_point(point)
    raw = _raw_tx(selected + (tapscript, control))
    parsed = parse_bitcoin_transaction(raw)
    chain = sha256(b"regtest genesis").digest()
    context = sha256(b"sidecar context").digest()
    tree = LabelCommitmentTree.from_input_encodings(
        (_encoding(input_bits, 100), _encoding(input_bits, 1000)),
        context_digest=context,
        slot_id=0,
        input_bits=input_bits,
        program_seed=sha256(b"seed").digest(),
    )
    artifact = b"sealed" * 100
    descriptor = slot_descriptor_from_artifact(
        0,
        artifact,
        input_label_commitment=tree.root,
        independence_nonce=b"sidecar independent nonce",
    )
    authorizer_secret = 41
    participant_secrets = (11, 13)
    activation, guide, participants = dealer_split_fixture(
        tree,
        chain_genesis_hash=chain,
        counterproof_txid=parsed.txid,
        artifact_root=descriptor.artifact_root,
        participant_secrets=participant_secrets,
        request_authorizer_pubkey=public_key(authorizer_secret),
        rollback_witness_pubkeys=(public_key(59),),
        deterministic_seed=b"sidecar deterministic fixture",
    )
    binding = BitcoinAuthorizationBinding.from_raw_transaction(
        raw, chain_genesis_hash=chain, authorization_input_index=0
    )
    request = issue_committee_request(
        activation,
        point=point,
        bitcoin_binding=binding,
        request_authorizer_secret=authorizer_secret,
    )
    policy = SignedBitcoinWitnessPolicy.create(
        UnsignedBitcoinWitnessPolicy(
            context_digest=context,
            activation_digest=activation.digest,
            slot_id=0,
            authorization_input_index=0,
            input_bits=input_bits,
            tapscript_hash=witness_script_hash(tapscript),
            control_block_hash=witness_control_hash(control),
            rules=rules,
        ),
        activation=activation,
        participant_secrets=participant_secrets,
    )
    ledger = DurableSlotLedger(
        tmp_path / "ledger.sqlite", context_digest=context, slot_count=1
    )
    witness = SqliteRollbackWitness(
        tmp_path / "rollback-witness.sqlite", witness_secret=59
    )
    return raw, parsed, activation, guide, participants[0], request, ledger, witness, policy


class FakeCore:
    def __init__(self, raw: bytes, *, block_hash: str, confirmations: int = 6) -> None:
        self.raw = raw
        self.parsed = parse_bitcoin_transaction(raw)
        self.block_hash = block_hash
        self.confirmations = confirmations

    def call(self, method: str, *params: object) -> object:
        if method == "getblockhash":
            assert params == (0,)
            return sha256(b"regtest genesis").hexdigest()
        if method == "getrawtransaction":
            return {
                "hex": self.raw.hex(),
                "txid": self.parsed.txid.hex(),
                "hash": self.parsed.wtxid.hex(),
                "blockhash": self.block_hash,
                "confirmations": self.confirmations,
            }
        if method == "getblockheader":
            return {"height": 1234, "confirmations": self.confirmations}
        raise AssertionError(method)


def test_sidecar_core_checks_durable_burn_and_atomic_idempotent_output(tmp_path):
    raw, parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)
    block_hash = "ab" * 32
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=FakeCore(raw, block_hash=block_hash),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    output = tmp_path / "release.bin"
    first, observation, receipts, created = service.issue(
        request=request,
        raw_transaction=raw,
        block_hash=block_hash,
        output_path=output,
    )
    assert created
    assert len(receipts) == 1 and receipts[0].verify()
    assert output.read_bytes() == first.compact_bytes
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert observation.txid == parsed.txid.hex()
    assert ledger.use(0).state == "success"

    second, _observation, replay_receipts, created_again = service.issue(
        request=request,
        raw_transaction=raw,
        block_hash=block_hash,
        output_path=output,
    )
    assert not created_again
    assert replay_receipts[0].generation >= receipts[0].generation
    assert second.compact_bytes == first.compact_bytes
    assert ledger.verify_audit_chain()


def test_core_mismatch_or_insufficient_confirmations_fails_before_burn(tmp_path):
    raw, _parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)
    block_hash = "cd" * 32
    other_raw = raw.replace(
        (90_000).to_bytes(8, "little"),
        (90_001).to_bytes(8, "little"),
        1,
    )
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=FakeCore(other_raw, block_hash=block_hash),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    with pytest.raises(ReleaseSidecarError, match="raw transaction"):
        service.issue(
            request=request,
            raw_transaction=raw,
            block_hash=block_hash,
            output_path=tmp_path / "no.bin",
        )
    assert ledger.remaining == 1

    shallow = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=FakeCore(raw, block_hash=block_hash, confirmations=2),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    with pytest.raises(ReleaseSidecarError, match="confirmations"):
        shallow.issue(
            request=request,
            raw_transaction=raw,
            block_hash=block_hash,
            output_path=tmp_path / "no2.bin",
        )
    assert ledger.remaining == 1


def test_secret_state_round_trip_and_permission_gate(tmp_path):
    _raw, _parsed, _activation, _guide, participant, _request, _ledger, _witness, _policy = _fixture(tmp_path)
    encoded = participant.compact_secret_bytes
    assert ParticipantSlotSecrets.parse_secret_bytes(encoded) == participant
    path = tmp_path / "participant.secrets"
    path.write_bytes(encoded)
    os.chmod(path, 0o644)
    with pytest.raises(ReleaseSidecarError, match="permissions"):
        require_secret_file_permissions(path)
    os.chmod(path, 0o600)
    require_secret_file_permissions(path)


def test_atomic_write_once_rejects_different_existing_response(tmp_path):
    path = tmp_path / "response.bin"
    assert atomic_write_once(path, b"one")
    assert not atomic_write_once(path, b"one")
    with pytest.raises(ReleaseSidecarError, match="different"):
        atomic_write_once(path, b"two")


def test_sidecar_refuses_restored_ledger_before_emitting_share(tmp_path):
    import shutil
    from pathlib import Path

    raw, _parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)
    block_hash = "ef" * 32
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=FakeCore(raw, block_hash=block_hash),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    ledger.checkpoint()
    backup = tmp_path / "available-ledger.sqlite"
    shutil.copy2(ledger.path, backup)
    service.issue(
        request=request,
        raw_transaction=raw,
        block_hash=block_hash,
        output_path=tmp_path / "first-release.bin",
    )

    for suffix in ("", "-wal", "-shm"):
        Path(str(ledger.path) + suffix).unlink(missing_ok=True)
    shutil.copy2(backup, ledger.path)
    restored = DurableSlotLedger(ledger.path, context_digest=activation.unsigned.context_digest, slot_count=1)
    with pytest.raises(ReleaseSidecarError, match="rollback-witness bootstrap"):
        ParticipantReleaseSidecar(
            activation=activation,
            label_guide=guide,
            participant=participant,
            ledger=restored,
            bitcoin_core=FakeCore(raw, block_hash=block_hash),
            minimum_confirmations=6,
            rollback_witnesses=(witness,),
            witness_policy=policy,
        )
    assert not (tmp_path / "second-release.bin").exists()

class ReorgRaceCore(FakeCore):
    def __init__(self, raw: bytes, *, block_hash: str, confirmations: int = 6) -> None:
        super().__init__(raw, block_hash=block_hash, confirmations=confirmations)
        self.header_calls = 0

    def call(self, method: str, *params: object) -> object:
        if method == "getblockheader":
            self.header_calls += 1
            return {
                "height": 1234 if self.header_calls == 1 else 1235,
                "confirmations": self.confirmations,
            }
        return super().call(method, *params)


def test_reorg_race_after_burn_aborts_without_emitting_share(tmp_path):
    raw, _parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)
    block_hash = "12" * 32
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=ReorgRaceCore(raw, block_hash=block_hash),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    output = tmp_path / "must-not-exist.bin"
    with pytest.raises(ReleaseSidecarError, match="inclusion changed"):
        service.issue(
            request=request,
            raw_transaction=raw,
            block_hash=block_hash,
            output_path=output,
        )
    assert not output.exists()
    assert ledger.use(0).state == "abort"
    assert ledger.remaining == 0
    assert ledger.verify_audit_chain()


def test_sidecar_rejects_signed_point_not_selected_by_witness_before_burn(tmp_path):
    raw, _parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)
    wrong = issue_committee_request(
        activation,
        point=multiply(G1, 778, group="g1"),
        bitcoin_binding=request.bitcoin_binding,
        request_authorizer_secret=41,
    )
    block_hash = "34" * 32
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=FakeCore(raw, block_hash=block_hash),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    with pytest.raises(ReleaseSidecarError, match="off-chain request point"):
        service.issue(
            request=wrong,
            raw_transaction=raw,
            block_hash=block_hash,
            output_path=tmp_path / "must-not-exist.bin",
        )
    assert ledger.remaining == 1


def test_core_genesis_mismatch_fails_before_burn(tmp_path):
    raw, _parsed, activation, guide, participant, request, ledger, witness, policy = _fixture(tmp_path)

    class WrongGenesisCore(FakeCore):
        def call(self, method: str, *params: object) -> object:
            if method == "getblockhash":
                return sha256(b"another-chain").hexdigest()
            return super().call(method, *params)

    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=WrongGenesisCore(raw, block_hash="56" * 32),
        minimum_confirmations=6,
        rollback_witnesses=(witness,),
        witness_policy=policy,
    )
    with pytest.raises(ReleaseSidecarError, match="chain genesis"):
        service.issue(
            request=request,
            raw_transaction=raw,
            block_hash="56" * 32,
            output_path=tmp_path / "must-not-exist.bin",
        )
    assert ledger.remaining == 1


def test_secret_reader_rejects_symlink_directory_and_oversize(tmp_path):
    path = tmp_path / "secret.bin"
    path.write_bytes(b"secret")
    os.chmod(path, 0o600)
    assert read_secret_file_secure(path) == b"secret"

    link = tmp_path / "secret-link"
    link.symlink_to(path)
    with pytest.raises(ReleaseSidecarError, match="symlink"):
        read_secret_file_secure(link)
    with pytest.raises(ReleaseSidecarError, match="regular"):
        require_secret_file_permissions(tmp_path)
    with pytest.raises(ReleaseSidecarError, match="size limit"):
        read_secret_file_secure(path, maximum_bytes=3)


def test_remote_bitcoin_rpc_requires_https_and_pinned_mutual_tls(tmp_path):
    with pytest.raises(ReleaseSidecarError, match="requires HTTPS"):
        BitcoinCoreRpcConfig(url="http://example.com:8332", username="u", password="p")
    BitcoinCoreRpcConfig(url="http://127.0.0.1:18443", username="u", password="p")
    with pytest.raises(ReleaseSidecarError, match="pinned CA and mutual TLS"):
        BitcoinCoreRpcConfig(url="https://core.example.com", username="u", password="p")
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    for path in (ca, cert, key):
        path.write_bytes(b"test certificate fixture")
    key.chmod(0o600)
    BitcoinCoreRpcConfig(
        url="https://core.example.com",
        username="u",
        password="p",
        ca_file=ca,
        client_cert_file=cert,
        client_key_file=key,
    )
    with pytest.raises(ReleaseSidecarError, match="credentials must not appear"):
        BitcoinCoreRpcConfig(url="https://u:p@core.example.com", username="u", password="p")
    with pytest.raises(ReleaseSidecarError, match="query or fragment"):
        BitcoinCoreRpcConfig(url="http://127.0.0.1:18443/?cookie=secret", username="u", password="p")


def test_duplicate_rollback_witness_identity_is_rejected(tmp_path):
    raw, _parsed, activation, guide, participant, _request, ledger, witness, policy = _fixture(tmp_path)
    with pytest.raises(ReleaseSidecarError, match="identities are duplicated"):
        ParticipantReleaseSidecar(
            activation=activation,
            label_guide=guide,
            participant=participant,
            ledger=ledger,
            bitcoin_core=FakeCore(raw, block_hash="78" * 32),
            minimum_confirmations=6,
            rollback_witnesses=(witness, witness),
            witness_policy=policy,
        )


def test_sidecar_rejects_unpinned_rollback_witness_identity(tmp_path):
    raw, _parsed, activation, guide, participant, _request, ledger, _witness, policy = _fixture(tmp_path)
    substituted = SqliteRollbackWitness(
        tmp_path / "substituted-witness.sqlite", witness_secret=61
    )
    with pytest.raises(ReleaseSidecarError, match="differ from the signed activation"):
        ParticipantReleaseSidecar(
            activation=activation,
            label_guide=guide,
            participant=participant,
            ledger=ledger,
            bitcoin_core=FakeCore(raw, block_hash="90" * 32),
            minimum_confirmations=6,
            rollback_witnesses=(substituted,),
            witness_policy=policy,
        )
    assert ledger.remaining == 1


def test_atomic_output_rejects_shared_or_world_writable_parent(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    shared.chmod(0o777)
    with pytest.raises(ReleaseSidecarError, match="group/world writable"):
        atomic_write_once(shared / "release.bin", b"secret")


def test_core_client_key_requires_private_regular_file(tmp_path):
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    for path in (ca, cert, key):
        path.write_text("fixture")
    ca.chmod(0o644)
    cert.chmod(0o644)
    key.chmod(0o644)
    with pytest.raises(ReleaseSidecarError, match="permissions"):
        BitcoinCoreRpcConfig(
            url="https://core.example:8332",
            username="rpc",
            password="secret",
            ca_file=ca,
            client_cert_file=cert,
            client_key_file=key,
        )
    key.chmod(0o600)
    config = BitcoinCoreRpcConfig(
        url="https://core.example:8332",
        username="rpc",
        password="secret",
        ca_file=ca,
        client_cert_file=cert,
        client_key_file=key,
    )
    assert config.client_key_file == key
