from __future__ import annotations

"""Two-phase authorization for non-malleable adaptive Bitcoin witnesses.

Phase 1 (before broadcast)
--------------------------
The request authorizer signs a canonical point and the precommitted stripped
transaction plan.  Every committee participant durably burns the slot and
releases only its XOR shares of the 512 selected DFB input labels.  The public
coordinator reconstructs the labels and verifies their hashes against the
committee-signed tapscript policy.  No program-sealing seed share is released.

Phase 2 (after Bitcoin confirmation)
------------------------------------
The confirmed witness contains those labels as hash-lock preimages.  A second
request binds txid, wtxid and the complete witness.  After Bitcoin Core and the
signed witness policy agree, participants release only their program-seed
shares.  The already-burned ledger is resumed through the stable phase-1
binding, then finalized by the networked sidecar.

An observer can copy the confirmed witness and therefore the same point.  It
cannot change a bit without finding an unrevealed 128-bit label preimage.  This
is the protocol property needed; raw witness non-malleability is neither
claimed nor required.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Sequence

from .adaptive_sealing import open_fused_slot, program_seed_commitment
from .authorization_transaction_plan import AuthorizationTransactionPlan
from .authorized_labels import LABEL_BYTES, _ARTIFACT_ROOT_DOMAIN, _sha, _u as _label_u
from .bip340 import public_key, sign, verify
from .bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    derive_witness_selection,
    witness_item_hash,
)
from .bn254_real import affine, compress_g1, decompress_g1
from .committee_authorization import (
    CommitteeAuthorizationRequest,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
)
from .bounded_mpc_embryo import SignedBoundedEmbryoManifest
from .dfb_real import DfbProfile
from .durable_slot_ledger import DurableSlotLedger, SlotTerminalError
from .embryo_mask_fusion import FusedSlotReplay, parse_fused_slot, replay_fused_slot


_HASH = 32
_SIG = 64
_LABEL = 16
_PRE_MAGIC = b"RLPA2501"
_WITNESS_RESPONSE_MAGIC = b"RLWR2501"
_SEED_RESPONSE_MAGIC = b"RLSR2502"
_PRE_SIGN_DOMAIN = b"ranklock/witness-preauthorization-sign/v1\x00"
_PRE_DIGEST_DOMAIN = b"ranklock/witness-preauthorization/v1\x00"
_WITNESS_RESPONSE_SIGN_DOMAIN = b"ranklock/witness-share-response-sign/v1\x00"
_WITNESS_RESPONSE_DIGEST_DOMAIN = b"ranklock/witness-share-response/v1\x00"
_SEED_RESPONSE_SIGN_DOMAIN = b"ranklock/seed-response-sign/v1\x00"
_SEED_RESPONSE_DIGEST_DOMAIN = b"ranklock/seed-response/v1\x00"
_INPUT_DIGEST_DOMAIN = b"ranklock/two-phase-input/v1\x00"


class TwoPhaseAuthorizationError(RuntimeError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise TwoPhaseAuthorizationError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _h(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        digest.update(bytes(part))
    return digest.digest()


def _xor(values: Sequence[bytes], width: int) -> bytes:
    if not values or any(len(bytes(value)) != width for value in values):
        raise TwoPhaseAuthorizationError("XOR share vector has the wrong width")
    result = bytearray(width)
    for value in values:
        for index, byte in enumerate(bytes(value)):
            result[index] ^= byte
    return bytes(result)


def _point_values(point_encoding: bytes) -> tuple[object, tuple[int, int]]:
    try:
        point = decompress_g1(bytes(point_encoding))
        coordinates = affine(point)
    except Exception as exc:
        raise TwoPhaseAuthorizationError("preauthorization point is not canonical") from exc
    if coordinates is None or compress_g1(point) != bytes(point_encoding):
        raise TwoPhaseAuthorizationError("preauthorization point is infinity/non-canonical")
    return point, (int(coordinates[0].n), int(coordinates[1].n))


def _participant_descriptor(
    activation: SignedCommitteeActivation, participant_index: int
):
    if not 0 <= int(participant_index) < len(activation.unsigned.participants):
        raise TwoPhaseAuthorizationError("participant index is outside activation")
    descriptor = activation.unsigned.participants[int(participant_index)]
    if descriptor.participant_index != int(participant_index):
        raise TwoPhaseAuthorizationError("activation participant mapping is non-canonical")
    return descriptor


@dataclass(frozen=True, slots=True)
class WitnessPreauthorizationRequest:
    context_digest: bytes
    activation_digest: bytes
    slot_id: int
    point_encoding: bytes
    transaction_plan_digest: bytes
    stripped_transaction_digest: bytes
    request_authorizer_pubkey: bytes
    request_signature: bytes
    schema: str = "ranklock-witness-preauthorization-request-v1"

    def __post_init__(self) -> None:
        for value, name in (
            (self.context_digest, "context digest"),
            (self.activation_digest, "activation digest"),
            (self.point_encoding, "point encoding"),
            (self.transaction_plan_digest, "transaction plan digest"),
            (self.stripped_transaction_digest, "stripped transaction digest"),
            (self.request_authorizer_pubkey, "request authorizer public key"),
        ):
            if len(bytes(value)) != _HASH:
                raise TwoPhaseAuthorizationError(f"{name} must be 32 bytes")
        if len(bytes(self.request_signature)) != _SIG:
            raise TwoPhaseAuthorizationError("preauthorization signature must be 64 bytes")
        if not 0 <= int(self.slot_id) < 2**32:
            raise TwoPhaseAuthorizationError("slot id does not fit u32")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _PRE_MAGIC
            + bytes(self.context_digest)
            + bytes(self.activation_digest)
            + _u(self.slot_id, 4, "slot id")
            + bytes(self.point_encoding)
            + bytes(self.transaction_plan_digest)
            + bytes(self.stripped_transaction_digest)
            + bytes(self.request_authorizer_pubkey)
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_PRE_SIGN_DOMAIN, self.unsigned_bytes)

    @property
    def digest(self) -> bytes:
        return _h(_PRE_DIGEST_DOMAIN, self.signing_message, self.request_signature)

    @property
    def input_digest(self) -> bytes:
        return _h(_INPUT_DIGEST_DOMAIN, self.point_encoding)

    @property
    def compact_bytes(self) -> bytes:
        return self.unsigned_bytes + bytes(self.request_signature)

    def verify(
        self,
        activation: SignedCommitteeActivation,
        plan: AuthorizationTransactionPlan,
    ) -> bool:
        unsigned = activation.unsigned
        slot = int(self.slot_id)
        return bool(
            activation.verify()
            and self.context_digest == unsigned.context_digest
            and self.activation_digest == activation.digest
            and slot == unsigned.slot_id
            and slot < len(plan.templates)
            and self.transaction_plan_digest == plan.digest
            and self.stripped_transaction_digest == plan.templates[slot].stripped_digest
            and plan.chain_genesis_hash == unsigned.chain_genesis_hash
            and plan.templates[slot].txid == unsigned.counterproof_txid
            and self.request_authorizer_pubkey == unsigned.request_authorizer_pubkey
            and verify(
                self.signing_message,
                self.request_authorizer_pubkey,
                self.request_signature,
            )
        )

    @classmethod
    def parse_compact(cls, raw: bytes) -> "WitnessPreauthorizationRequest":
        raw = bytes(raw)
        expected = 8 + 32 + 32 + 4 + 32 + 32 + 32 + 32 + 64
        if len(raw) != expected or raw[:8] != _PRE_MAGIC:
            raise TwoPhaseAuthorizationError("invalid preauthorization framing")
        cursor = 8
        result = cls(
            raw[cursor : cursor + 32],
            raw[cursor + 32 : cursor + 64],
            int.from_bytes(raw[cursor + 64 : cursor + 68], "big"),
            raw[cursor + 68 : cursor + 100],
            raw[cursor + 100 : cursor + 132],
            raw[cursor + 132 : cursor + 164],
            raw[cursor + 164 : cursor + 196],
            raw[cursor + 196 : cursor + 260],
        )
        if result.compact_bytes != raw:
            raise TwoPhaseAuthorizationError("non-canonical preauthorization request")
        return result


def issue_witness_preauthorization_request(
    activation: SignedCommitteeActivation,
    plan: AuthorizationTransactionPlan,
    *,
    point: object,
    request_authorizer_secret: int,
) -> WitnessPreauthorizationRequest:
    if not activation.verify():
        raise TwoPhaseAuthorizationError("committee activation failed verification")
    slot = activation.unsigned.slot_id
    if slot >= len(plan.templates):
        raise TwoPhaseAuthorizationError("activation slot is absent from transaction plan")
    if public_key(int(request_authorizer_secret)) != activation.unsigned.request_authorizer_pubkey:
        raise TwoPhaseAuthorizationError("request authorizer secret does not match activation")
    placeholder = WitnessPreauthorizationRequest(
        activation.unsigned.context_digest,
        activation.digest,
        slot,
        compress_g1(point),  # type: ignore[arg-type]
        plan.digest,
        plan.templates[slot].stripped_digest,
        activation.unsigned.request_authorizer_pubkey,
        bytes(_SIG),
    )
    request = WitnessPreauthorizationRequest(
        placeholder.context_digest,
        placeholder.activation_digest,
        placeholder.slot_id,
        placeholder.point_encoding,
        placeholder.transaction_plan_digest,
        placeholder.stripped_transaction_digest,
        placeholder.request_authorizer_pubkey,
        sign(placeholder.signing_message, int(request_authorizer_secret)),
    )
    if not request.verify(activation, plan):
        raise TwoPhaseAuthorizationError("internally generated preauthorization failed")
    return request


@dataclass(frozen=True, slots=True)
class ParticipantWitnessShareResponse:
    activation_digest: bytes
    preauthorization_digest: bytes
    participant_index: int
    participant_pubkey: bytes
    input_bits: int
    selected_label_shares: tuple[bytes, ...]
    participant_signature: bytes
    schema: str = "ranklock-participant-witness-share-response-v1"

    def __post_init__(self) -> None:
        for value, name in (
            (self.activation_digest, "activation digest"),
            (self.preauthorization_digest, "preauthorization digest"),
            (self.participant_pubkey, "participant public key"),
        ):
            if len(bytes(value)) != _HASH:
                raise TwoPhaseAuthorizationError(f"{name} must be 32 bytes")
        if not 1 < int(self.input_bits) < 2**16:
            raise TwoPhaseAuthorizationError("input width is invalid")
        if len(self.selected_label_shares) != 2 * int(self.input_bits):
            raise TwoPhaseAuthorizationError("selected label-share count mismatch")
        if any(len(bytes(share)) != _LABEL for share in self.selected_label_shares):
            raise TwoPhaseAuthorizationError("selected label shares must be 16 bytes")
        if len(bytes(self.participant_signature)) != _SIG:
            raise TwoPhaseAuthorizationError("witness-share signature must be 64 bytes")

    @property
    def header_bytes(self) -> bytes:
        return (
            _WITNESS_RESPONSE_MAGIC
            + bytes(self.activation_digest)
            + bytes(self.preauthorization_digest)
            + _u(self.participant_index, 4, "participant index")
            + bytes(self.participant_pubkey)
            + _u(self.input_bits, 2, "input bits")
        )

    @property
    def shares_digest(self) -> bytes:
        return _h(
            _WITNESS_RESPONSE_DIGEST_DOMAIN,
            _u(self.input_bits, 2, "input bits"),
            *self.selected_label_shares,
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_WITNESS_RESPONSE_SIGN_DOMAIN, self.header_bytes, self.shares_digest)

    @property
    def compact_bytes(self) -> bytes:
        return (
            self.header_bytes
            + b"".join(bytes(share) for share in self.selected_label_shares)
            + bytes(self.participant_signature)
        )

    def verify_signature(self) -> bool:
        return verify(self.signing_message, self.participant_pubkey, self.participant_signature)

    @classmethod
    def parse_compact(cls, raw: bytes) -> "ParticipantWitnessShareResponse":
        raw = bytes(raw)
        fixed = 8 + 32 + 32 + 4 + 32 + 2
        if len(raw) < fixed + _SIG or raw[:8] != _WITNESS_RESPONSE_MAGIC:
            raise TwoPhaseAuthorizationError("invalid witness-share response framing")
        input_bits = int.from_bytes(raw[108:110], "big")
        expected = fixed + 2 * input_bits * _LABEL + _SIG
        if len(raw) != expected:
            raise TwoPhaseAuthorizationError("witness-share response length mismatch")
        cursor = fixed
        shares = tuple(
            raw[cursor + _LABEL * i : cursor + _LABEL * (i + 1)]
            for i in range(2 * input_bits)
        )
        result = cls(
            raw[8:40],
            raw[40:72],
            int.from_bytes(raw[72:76], "big"),
            raw[76:108],
            input_bits,
            shares,
            raw[-_SIG:],
        )
        if result.compact_bytes != raw:
            raise TwoPhaseAuthorizationError("non-canonical witness-share response")
        return result


@dataclass(frozen=True, slots=True)
class ReconstructedWitnessLabels:
    preauthorization: WitnessPreauthorizationRequest
    labels: tuple[bytes, ...]
    selected_bits: tuple[int, ...]
    participant_pubkeys: tuple[bytes, ...]
    schema: str = "ranklock-reconstructed-witness-labels-v1"

    @property
    def witness_stack_items(self) -> tuple[bytes, ...]:
        return self.labels


def _validate_preauthorization_static(
    *,
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    plan: AuthorizationTransactionPlan,
    policy: SignedBitcoinWitnessPolicy,
    participant: ParticipantSlotSecrets | None = None,
) -> None:
    if not preauthorization.verify(activation, plan):
        raise TwoPhaseAuthorizationError("preauthorization verification failed")
    if not policy.verify(activation):
        raise TwoPhaseAuthorizationError("witness policy verification failed")
    if (
        policy.unsigned.context_digest != preauthorization.context_digest
        or policy.unsigned.slot_id != preauthorization.slot_id
        or policy.unsigned.input_bits != activation.unsigned.input_bits
        or len(policy.unsigned.rules) != 2 * activation.unsigned.input_bits
        or any(rule.kind != 1 for rule in policy.unsigned.rules)
    ):
        raise TwoPhaseAuthorizationError("witness policy does not match preauthorization")
    if participant is not None:
        descriptor = _participant_descriptor(activation, participant.participant_index)
        if (
            participant.context_digest != activation.unsigned.context_digest
            or participant.slot_id != activation.unsigned.slot_id
            or participant.input_bits != activation.unsigned.input_bits
            or participant.participant_pubkey != descriptor.participant_pubkey
            or participant.share_root != descriptor.share_root
        ):
            raise TwoPhaseAuthorizationError("participant secrets do not match activation")


def prepare_witness_share_response(
    *,
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    plan: AuthorizationTransactionPlan,
    policy: SignedBitcoinWitnessPolicy,
    participant: ParticipantSlotSecrets,
    ledger: DurableSlotLedger,
) -> ParticipantWitnessShareResponse:
    _validate_preauthorization_static(
        activation=activation,
        preauthorization=preauthorization,
        plan=plan,
        policy=policy,
        participant=participant,
    )
    if ledger.context_digest != preauthorization.context_digest:
        raise TwoPhaseAuthorizationError("participant ledger is for another context")

    use = ledger.begin(
        preauthorization.slot_id,
        context_digest=preauthorization.context_digest,
        input_digest=preauthorization.input_digest,
        authorization_digest=preauthorization.digest,
        chain_binding_digest=preauthorization.stripped_transaction_digest,
    )
    if use.terminal and use.state != "success":
        raise TwoPhaseAuthorizationError(
            f"preauthorization previously terminated as {use.state}"
        )
    try:
        _point, values = _point_values(preauthorization.point_encoding)
        selected: list[bytes] = []
        for flat_index, pair in enumerate(participant.label_share_pairs):
            coordinate, bit = divmod(flat_index, participant.input_bits)
            selected.append(bytes(pair[(values[coordinate] >> bit) & 1]))
        placeholder = ParticipantWitnessShareResponse(
            activation.digest,
            preauthorization.digest,
            participant.participant_index,
            participant.participant_pubkey,
            participant.input_bits,
            tuple(selected),
            bytes(_SIG),
        )
        response = ParticipantWitnessShareResponse(
            placeholder.activation_digest,
            placeholder.preauthorization_digest,
            placeholder.participant_index,
            placeholder.participant_pubkey,
            placeholder.input_bits,
            placeholder.selected_label_shares,
            sign(placeholder.signing_message, participant.participant_secret),
        )
        if not response.verify_signature():  # pragma: no cover - internal defense
            raise TwoPhaseAuthorizationError("generated witness-share signature failed")
        return response
    except Exception as exc:
        try:
            ledger.finalize(preauthorization.slot_id, outcome="malformed")
        except SlotTerminalError:
            pass
        if isinstance(exc, TwoPhaseAuthorizationError):
            raise
        raise TwoPhaseAuthorizationError(f"witness-share preparation failed: {exc}") from exc


def reconstruct_witness_labels(
    *,
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    plan: AuthorizationTransactionPlan,
    policy: SignedBitcoinWitnessPolicy,
    responses: Sequence[ParticipantWitnessShareResponse],
) -> ReconstructedWitnessLabels:
    _validate_preauthorization_static(
        activation=activation,
        preauthorization=preauthorization,
        plan=plan,
        policy=policy,
    )
    participants = activation.unsigned.participants
    if len(responses) != len(participants):
        raise TwoPhaseAuthorizationError("all n-of-n witness-share responses are required")
    by_index = {response.participant_index: response for response in responses}
    if len(by_index) != len(responses) or set(by_index) != set(range(len(participants))):
        raise TwoPhaseAuthorizationError("witness-share response set is non-canonical")
    ordered: list[ParticipantWitnessShareResponse] = []
    for descriptor in participants:
        response = by_index[descriptor.participant_index]
        if (
            response.activation_digest != activation.digest
            or response.preauthorization_digest != preauthorization.digest
            or response.participant_pubkey != descriptor.participant_pubkey
            or response.input_bits != activation.unsigned.input_bits
            or not response.verify_signature()
        ):
            raise TwoPhaseAuthorizationError("witness-share response failed verification")
        ordered.append(response)

    _point, values = _point_values(preauthorization.point_encoding)
    labels: list[bytes] = []
    selected_bits: list[int] = []
    for flat_index, rule in enumerate(policy.unsigned.rules):
        coordinate, bit = divmod(flat_index, activation.unsigned.input_bits)
        selected_bit = (values[coordinate] >> bit) & 1
        label = _xor(
            tuple(response.selected_label_shares[flat_index] for response in ordered),
            _LABEL,
        )
        expected = rule.one_hash if selected_bit else rule.zero_hash
        if witness_item_hash(label) != expected:
            raise TwoPhaseAuthorizationError(
                "reconstructed witness label does not match signed policy"
            )
        labels.append(label)
        selected_bits.append(selected_bit)
    return ReconstructedWitnessLabels(
        preauthorization,
        tuple(labels),
        tuple(selected_bits),
        tuple(response.participant_pubkey for response in ordered),
    )


@dataclass(frozen=True, slots=True)
class ParticipantSeedResponse:
    activation_digest: bytes
    preauthorization_digest: bytes
    confirmation_request_digest: bytes
    participant_index: int
    participant_pubkey: bytes
    program_seed_share: bytes
    participant_signature: bytes
    schema: str = "ranklock-participant-seed-response-v1"

    def __post_init__(self) -> None:
        for value, name in (
            (self.activation_digest, "activation digest"),
            (self.preauthorization_digest, "preauthorization digest"),
            (self.confirmation_request_digest, "confirmation request digest"),
            (self.participant_pubkey, "participant public key"),
            (self.program_seed_share, "program seed share"),
        ):
            if len(bytes(value)) != _HASH:
                raise TwoPhaseAuthorizationError(f"{name} must be 32 bytes")
        if len(bytes(self.participant_signature)) != _SIG:
            raise TwoPhaseAuthorizationError("seed-response signature must be 64 bytes")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _SEED_RESPONSE_MAGIC
            + bytes(self.activation_digest)
            + bytes(self.preauthorization_digest)
            + bytes(self.confirmation_request_digest)
            + _u(self.participant_index, 4, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.program_seed_share)
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_SEED_RESPONSE_SIGN_DOMAIN, self.unsigned_bytes)

    @property
    def digest(self) -> bytes:
        return _h(_SEED_RESPONSE_DIGEST_DOMAIN, self.signing_message, self.participant_signature)

    @property
    def compact_bytes(self) -> bytes:
        return self.unsigned_bytes + bytes(self.participant_signature)

    def verify_signature(self) -> bool:
        return verify(self.signing_message, self.participant_pubkey, self.participant_signature)

    @classmethod
    def parse_compact(cls, raw: bytes) -> "ParticipantSeedResponse":
        raw = bytes(raw)
        expected = 8 + 32 + 32 + 32 + 4 + 32 + 32 + 64
        if len(raw) != expected or raw[:8] != _SEED_RESPONSE_MAGIC:
            raise TwoPhaseAuthorizationError("invalid seed-response framing")
        result = cls(
            raw[8:40],
            raw[40:72],
            raw[72:104],
            int.from_bytes(raw[104:108], "big"),
            raw[108:140],
            raw[140:172],
            raw[172:236],
        )
        if result.compact_bytes != raw:
            raise TwoPhaseAuthorizationError("non-canonical seed response")
        return result


def prepare_seed_response(
    *,
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    confirmation_request: CommitteeAuthorizationRequest,
    raw_transaction: bytes,
    plan: AuthorizationTransactionPlan,
    policy: SignedBitcoinWitnessPolicy,
    participant: ParticipantSlotSecrets,
    ledger: DurableSlotLedger,
) -> ParticipantSeedResponse:
    _validate_preauthorization_static(
        activation=activation,
        preauthorization=preauthorization,
        plan=plan,
        policy=policy,
        participant=participant,
    )
    if not confirmation_request.verify(activation):
        raise TwoPhaseAuthorizationError("confirmation request failed verification")
    if (
        confirmation_request.point_encoding != preauthorization.point_encoding
        or confirmation_request.slot_id != preauthorization.slot_id
        or not plan.verify_raw_transaction(preauthorization.slot_id, raw_transaction)
        or not confirmation_request.bitcoin_binding.verify_raw_transaction(raw_transaction)
    ):
        raise TwoPhaseAuthorizationError("confirmation does not continue the burned preauthorization")
    selection = derive_witness_selection(
        raw_transaction,
        policy=policy,
        activation=activation,
    )
    if selection.point_encoding != preauthorization.point_encoding:
        raise TwoPhaseAuthorizationError("confirmed witness selects another point")
    use = ledger.begin(
        preauthorization.slot_id,
        context_digest=preauthorization.context_digest,
        input_digest=preauthorization.input_digest,
        authorization_digest=preauthorization.digest,
        chain_binding_digest=preauthorization.stripped_transaction_digest,
    )
    if use.terminal and use.state != "success":
        raise TwoPhaseAuthorizationError(
            f"preauthorization previously terminated as {use.state}"
        )
    placeholder = ParticipantSeedResponse(
        activation.digest,
        preauthorization.digest,
        confirmation_request.digest,
        participant.participant_index,
        participant.participant_pubkey,
        participant.program_seed_share,
        bytes(_SIG),
    )
    response = ParticipantSeedResponse(
        placeholder.activation_digest,
        placeholder.preauthorization_digest,
        placeholder.confirmation_request_digest,
        placeholder.participant_index,
        placeholder.participant_pubkey,
        placeholder.program_seed_share,
        sign(placeholder.signing_message, participant.participant_secret),
    )
    if not response.verify_signature():  # pragma: no cover - internal defense
        raise TwoPhaseAuthorizationError("generated seed-response signature failed")
    return response


def reconstruct_program_seed(
    *,
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    confirmation_request: CommitteeAuthorizationRequest,
    responses: Sequence[ParticipantSeedResponse],
) -> bytes:
    if not activation.verify() or not confirmation_request.verify(activation):
        raise TwoPhaseAuthorizationError("activation/confirmation verification failed")
    if confirmation_request.point_encoding != preauthorization.point_encoding:
        raise TwoPhaseAuthorizationError("confirmation point differs from preauthorization")
    participants = activation.unsigned.participants
    if len(responses) != len(participants):
        raise TwoPhaseAuthorizationError("all n-of-n seed responses are required")
    by_index = {response.participant_index: response for response in responses}
    if len(by_index) != len(responses) or set(by_index) != set(range(len(participants))):
        raise TwoPhaseAuthorizationError("seed response set is non-canonical")
    ordered: list[ParticipantSeedResponse] = []
    for descriptor in participants:
        response = by_index[descriptor.participant_index]
        if (
            response.activation_digest != activation.digest
            or response.preauthorization_digest != preauthorization.digest
            or response.confirmation_request_digest != confirmation_request.digest
            or response.participant_pubkey != descriptor.participant_pubkey
            or not response.verify_signature()
        ):
            raise TwoPhaseAuthorizationError("seed response failed verification")
        ordered.append(response)
    seed = _xor(tuple(response.program_seed_share for response in ordered), _HASH)
    if program_seed_commitment(seed) != activation.unsigned.program_seed_commitment_value:
        raise TwoPhaseAuthorizationError("reconstructed program seed differs from activation")
    return seed


@dataclass(frozen=True, slots=True)
class TwoPhaseFusedSlotExecution:
    replay: FusedSlotReplay
    reconstructed_witness: ReconstructedWitnessLabels
    program_seed: bytes
    schema: str = "ranklock-two-phase-fused-slot-execution-v1"


def execute_two_phase_authorized_fused_slot(
    *,
    manifest: SignedBoundedEmbryoManifest,
    required_manifest_pubkeys: Iterable[bytes],
    activation: SignedCommitteeActivation,
    preauthorization: WitnessPreauthorizationRequest,
    confirmation_request: CommitteeAuthorizationRequest,
    plan: AuthorizationTransactionPlan,
    policy: SignedBitcoinWitnessPolicy,
    witness_responses: Sequence[ParticipantWitnessShareResponse],
    seed_responses: Sequence[ParticipantSeedResponse],
    slot_artifact: bytes,
    profile: DfbProfile,
    nonce_namespace_base: int = 0,
) -> TwoPhaseFusedSlotExecution:
    """Open and replay one retained slot from the two-phase transcript.

    The witness labels and program seed are reconstructed from disjoint response
    types.  This prevents a pre-broadcast phase-one transcript from carrying
    enough material to open the retained program.
    """

    unsigned = activation.unsigned
    if not manifest.verify(
        required_pubkeys=required_manifest_pubkeys,
        expected_context_digest=unsigned.context_digest,
    ):
        raise TwoPhaseAuthorizationError("RankLock manifest failed verification")
    if not 0 <= unsigned.slot_id < manifest.unsigned.slot_count:
        raise TwoPhaseAuthorizationError("committee slot is outside RankLock manifest")
    descriptor = manifest.unsigned.slots[unsigned.slot_id]
    artifact = bytes(slot_artifact)
    artifact_root = _sha(
        _ARTIFACT_ROOT_DOMAIN,
        _label_u(unsigned.slot_id, 4, "slot id"),
        artifact,
    )
    if (
        descriptor.slot_id != unsigned.slot_id
        or descriptor.input_label_root != unsigned.aggregate_label_root
        or descriptor.artifact_root != unsigned.artifact_root
        or descriptor.artifact_root != artifact_root
        or descriptor.artifact_length != len(artifact)
    ):
        raise TwoPhaseAuthorizationError(
            "committee activation does not match retained slot"
        )

    reconstructed = reconstruct_witness_labels(
        activation=activation,
        preauthorization=preauthorization,
        plan=plan,
        policy=policy,
        responses=witness_responses,
    )
    seed = reconstruct_program_seed(
        activation=activation,
        preauthorization=preauthorization,
        confirmation_request=confirmation_request,
        responses=seed_responses,
    )
    point, _values = _point_values(preauthorization.point_encoding)
    plaintext = open_fused_slot(
        artifact,
        context_digest=unsigned.context_digest,
        slot_id=unsigned.slot_id,
        program_seed=seed,
    )
    namespace = int(nonce_namespace_base) + int(unsigned.slot_id)
    slot_profile = profile.with_nonce_namespace(namespace)
    program, mask_state = parse_fused_slot(plaintext, profile=slot_profile)
    labels = b"".join(reconstructed.labels)
    split = profile.input_bits * LABEL_BYTES
    if len(labels) != 2 * split:
        raise TwoPhaseAuthorizationError("reconstructed witness label vector is malformed")
    replay = replay_fused_slot(
        program=program,
        mask_state=mask_state,
        input_point=point,
        x_input_labels=labels[:split],
        y_input_labels=labels[split:],
    )
    return TwoPhaseFusedSlotExecution(replay, reconstructed, seed)
