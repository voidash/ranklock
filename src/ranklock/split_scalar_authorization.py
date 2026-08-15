from __future__ import annotations

"""Bitcoin-bound one-shot authorization for dealer-free split-scalar RankLock.

Each scalar-share participant owns one complete two-slot retained object and one
BIP340 release key.  This module binds that participant's online label/program-
seed release to the exact witness transaction confirmed by Bitcoin Core.  It
uses the same selector parser as the committee path, but has no dealer and no
cross-participant secret reconstruction: every participant independently burns
its local slot, anchors the transition at rollback witnesses, and emits one
ordinary :class:`~ranklock.authorized_labels.AuthorizedLabelRelease`.

Safety is N-of-N.  A corrupt participant can abort, but a corrupt N-1 coalition
cannot obtain the honest participant's second release, its positive-lock
preimage, or a third accepted evaluation.  The implementation remains Python
research code and is not a substitute for native constant-time hardening or an
independent audit.
"""

from dataclasses import dataclass
from hashlib import sha256
import os
from typing import Iterable

from .adaptive_sealing import parse_sealed_retained_object
from .authorization_transaction_plan import AuthorizationTransactionPlan
from .authorized_labels import (
    AuthorizedLabelRelease,
    EvaluationContext,
    LabelCommitmentTree,
    issue_label_release,
)
from .bip340 import public_key, sign, verify
from .bitcoin_authorization import BitcoinAuthorizationBinding
from .bitcoin_witness_selection import (
    BitcoinWitnessSelection,
    UnsignedBitcoinWitnessPolicy,
    derive_unsigned_witness_selection,
)
from .bn254_real import decompress_g1
from .durable_slot_ledger import DurableSlotLedger
from .release_sidecar import (
    BitcoinCoreReader,
    ConfirmedBitcoinObservation,
    ReleaseSidecarError,
    atomic_write_once,
    verify_confirmed_bitcoin_binding,
)
from .rollback_witness import (
    RollbackWitnessClient,
    RollbackWitnessError,
    RollbackWitnessReceipt,
    anchor_ledger_at_all_witnesses,
    require_rollback_witness_set,
    rollback_witness_set_digest,
)
from .split_scalar_lock import SignedSplitScalarBundle


_MAGIC = b"RLSP2512"
_MAGIC_SET = b"RLPS2512"
_POLICY_DOMAIN = b"ranklock/split-scalar/witness-policy/v3\x00"
_POLICY_SIGN_DOMAIN = b"ranklock/split-scalar/witness-policy-sign/v3\x00"
_POLICY_SET_DOMAIN = b"ranklock/split-scalar/witness-policy-set/v3\x00"
_INPUT_DOMAIN = b"ranklock/split-scalar/authorized-input/v1\x00"
_AUTH_DOMAIN = b"ranklock/split-scalar/authorization/v1\x00"
_CHAIN_DOMAIN = b"ranklock/split-scalar/chain-binding/v1\x00"
_HASH = 32
_SIG = 64


class SplitScalarAuthorizationError(RuntimeError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise SplitScalarAuthorizationError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _d(value: bytes, name: str) -> bytes:
    value = bytes(value)
    if len(value) != _HASH:
        raise SplitScalarAuthorizationError(f"{name} must be 32 bytes")
    return value


def _h(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        digest.update(bytes(part))
    return digest.digest()


@dataclass(frozen=True, slots=True)
class SignedSplitScalarWitnessPolicy:
    """One participant's signed Bitcoin witness-selection policy.

    ``unsigned.activation_digest`` is deliberately set to the signed split-
    scalar bundle digest.  The field name is inherited from the shared witness
    policy encoding, while this wrapper supplies the correct protocol-specific
    verification semantics.
    """

    participant_index: int
    participant_pubkey: bytes
    retained_object_digest: bytes
    transaction_plan_digest: bytes
    stripped_transaction_digest: bytes
    rollback_witness_set_digest: bytes
    minimum_confirmations: int
    unsigned: UnsignedBitcoinWitnessPolicy
    participant_signature: bytes
    schema: str = "ranklock-signed-split-scalar-witness-policy-v3"

    def __post_init__(self) -> None:
        if not 0 <= int(self.participant_index) < 2**16:
            raise SplitScalarAuthorizationError("participant index does not fit u16")
        for value, name in (
            (self.participant_pubkey, "participant public key"),
            (self.retained_object_digest, "retained-object digest"),
            (self.transaction_plan_digest, "transaction-plan digest"),
            (self.stripped_transaction_digest, "stripped-transaction digest"),
            (self.rollback_witness_set_digest, "rollback-witness-set digest"),
        ):
            _d(value, name)
        if not 1 <= int(self.minimum_confirmations) < 2**16:
            raise SplitScalarAuthorizationError("minimum confirmations must fit u16 and be positive")
        if len(bytes(self.participant_signature)) != _SIG:
            raise SplitScalarAuthorizationError("witness-policy signature must be 64 bytes")

    @property
    def header_bytes(self) -> bytes:
        encoded_unsigned = self.unsigned.encoded
        return (
            _MAGIC
            + _u(self.participant_index, 2, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.retained_object_digest)
            + bytes(self.transaction_plan_digest)
            + bytes(self.stripped_transaction_digest)
            + bytes(self.rollback_witness_set_digest)
            + _u(self.minimum_confirmations, 2, "minimum confirmations")
            + _u(len(encoded_unsigned), 4, "unsigned witness-policy length")
        )

    @property
    def signing_message(self) -> bytes:
        return _h(
            _POLICY_SIGN_DOMAIN,
            self.header_bytes,
            self.unsigned.digest,
        )

    @property
    def compact_bytes(self) -> bytes:
        return self.header_bytes + self.unsigned.encoded + bytes(self.participant_signature)

    @property
    def digest(self) -> bytes:
        return _h(_POLICY_DOMAIN, self.compact_bytes)

    def verify(
        self,
        *,
        bundle: SignedSplitScalarBundle,
        plan: AuthorizationTransactionPlan,
    ) -> bool:
        try:
            if not bundle.verify_signatures():
                return False
            index = int(self.participant_index)
            if index >= len(bundle.unsigned.contributions):
                return False
            contribution = bundle.unsigned.contributions[index]
            slot = int(self.unsigned.slot_id)
            if slot >= len(plan.templates):
                return False
            template = plan.templates[slot]
            return bool(
                self.participant_pubkey == contribution.participant_pubkey
                and self.retained_object_digest == contribution.retained_object_digest
                and self.transaction_plan_digest == plan.digest
                and self.stripped_transaction_digest == template.stripped_digest
                and self.unsigned.context_digest == bundle.unsigned.context_digest
                and self.unsigned.activation_digest == bundle.digest
                and self.unsigned.authorization_input_index
                == template.authorization_input_index
                and template.txid != bytes(_HASH)
                and verify(
                    self.signing_message,
                    self.participant_pubkey,
                    self.participant_signature,
                )
            )
        except Exception:
            return False

    @classmethod
    def create(
        cls,
        unsigned: UnsignedBitcoinWitnessPolicy,
        *,
        bundle: SignedSplitScalarBundle,
        plan: AuthorizationTransactionPlan,
        participant_index: int,
        participant_secret: int,
        rollback_witness_pubkeys: tuple[bytes, ...],
        minimum_confirmations: int = 6,
    ) -> "SignedSplitScalarWitnessPolicy":
        index = int(participant_index)
        if index >= len(bundle.unsigned.contributions):
            raise SplitScalarAuthorizationError("participant is absent from split-scalar bundle")
        if unsigned.activation_digest != bundle.digest:
            raise SplitScalarAuthorizationError("unsigned policy is not bound to split-scalar bundle")
        contribution = bundle.unsigned.contributions[index]
        if public_key(participant_secret) != contribution.participant_pubkey:
            raise SplitScalarAuthorizationError("participant secret does not match contribution")
        if unsigned.slot_id >= len(plan.templates):
            raise SplitScalarAuthorizationError("witness-policy slot is absent from plan")
        placeholder = cls(
            participant_index=index,
            participant_pubkey=contribution.participant_pubkey,
            retained_object_digest=contribution.retained_object_digest,
            transaction_plan_digest=plan.digest,
            stripped_transaction_digest=plan.templates[unsigned.slot_id].stripped_digest,
            rollback_witness_set_digest=rollback_witness_set_digest(rollback_witness_pubkeys),
            minimum_confirmations=int(minimum_confirmations),
            unsigned=unsigned,
            participant_signature=bytes(_SIG),
        )
        result = cls(
            participant_index=placeholder.participant_index,
            participant_pubkey=placeholder.participant_pubkey,
            retained_object_digest=placeholder.retained_object_digest,
            transaction_plan_digest=placeholder.transaction_plan_digest,
            stripped_transaction_digest=placeholder.stripped_transaction_digest,
            rollback_witness_set_digest=placeholder.rollback_witness_set_digest,
            minimum_confirmations=placeholder.minimum_confirmations,
            unsigned=placeholder.unsigned,
            participant_signature=sign(placeholder.signing_message, participant_secret),
        )
        if not result.verify(bundle=bundle, plan=plan):  # pragma: no cover
            raise AssertionError("generated split-scalar witness policy failed verification")
        return result

    @classmethod
    def parse_compact(cls, raw: bytes) -> "SignedSplitScalarWitnessPolicy":
        raw = bytes(raw)
        fixed = 8 + 2 + 32 * 5 + 2 + 4
        if len(raw) < fixed + _SIG or raw[:8] != _MAGIC:
            raise SplitScalarAuthorizationError("invalid split-scalar witness-policy framing")
        cursor = 8
        participant_index = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        participant_pubkey = raw[cursor : cursor + 32]; cursor += 32
        retained_digest = raw[cursor : cursor + 32]; cursor += 32
        plan_digest = raw[cursor : cursor + 32]; cursor += 32
        stripped_digest = raw[cursor : cursor + 32]; cursor += 32
        rollback_set_digest = raw[cursor : cursor + 32]; cursor += 32
        minimum_confirmations = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        unsigned_length = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        if unsigned_length == 0 or cursor + unsigned_length + _SIG != len(raw):
            raise SplitScalarAuthorizationError("split-scalar witness-policy length mismatch")
        unsigned = UnsignedBitcoinWitnessPolicy.parse(raw[cursor : cursor + unsigned_length])
        cursor += unsigned_length
        result = cls(
            participant_index=participant_index,
            participant_pubkey=participant_pubkey,
            retained_object_digest=retained_digest,
            transaction_plan_digest=plan_digest,
            stripped_transaction_digest=stripped_digest,
            rollback_witness_set_digest=rollback_set_digest,
            minimum_confirmations=minimum_confirmations,
            unsigned=unsigned,
            participant_signature=raw[cursor : cursor + _SIG],
        )
        if result.compact_bytes != raw:
            raise SplitScalarAuthorizationError("non-canonical split-scalar witness policy")
        return result


@dataclass(frozen=True, slots=True)
class SplitScalarWitnessPolicySet:
    """Canonical N-of-N agreement on one common Bitcoin selector policy.

    Every scalar-share participant signs the *same* unsigned selector policy,
    while its wrapper also binds that participant's retained-object digest.
    The witness therefore carries only one 512-item point selector, not one
    private-label vector per participant.  After deriving the common point from
    Bitcoin, each participant releases its own independently committed labels.
    """

    policies: tuple[SignedSplitScalarWitnessPolicy, ...]
    schema: str = "ranklock-split-scalar-witness-policy-set-v3"

    def __post_init__(self) -> None:
        if not 2 <= len(self.policies) < 2**16:
            raise SplitScalarAuthorizationError(
                "split-scalar policy set requires at least two participants"
            )
        indexes = tuple(int(policy.participant_index) for policy in self.policies)
        if indexes != tuple(range(len(self.policies))):
            raise SplitScalarAuthorizationError(
                "split-scalar policy indexes must be canonical and contiguous"
            )
        common = self.policies[0].unsigned.encoded
        if any(policy.unsigned.encoded != common for policy in self.policies[1:]):
            raise SplitScalarAuthorizationError(
                "all split-scalar participants must sign one common selector policy"
            )
        if len({bytes(policy.participant_pubkey) for policy in self.policies}) != len(
            self.policies
        ):
            raise SplitScalarAuthorizationError("duplicate participant key in policy set")
        if len(
            {bytes(policy.rollback_witness_set_digest) for policy in self.policies}
        ) != 1:
            raise SplitScalarAuthorizationError(
                "split-scalar participants did not pin one rollback-witness identity set"
            )
        if len({int(policy.minimum_confirmations) for policy in self.policies}) != 1:
            raise SplitScalarAuthorizationError(
                "split-scalar participants did not pin one confirmation-depth policy"
            )

    @property
    def unsigned(self) -> UnsignedBitcoinWitnessPolicy:
        return self.policies[0].unsigned

    @property
    def slot_id(self) -> int:
        return int(self.unsigned.slot_id)

    @property
    def compact_bytes(self) -> bytes:
        return (
            _MAGIC_SET
            + _u(len(self.policies), 2, "policy count")
            + b"".join(
                _u(len(policy.compact_bytes), 4, "participant policy length")
                + policy.compact_bytes
                for policy in self.policies
            )
        )

    @property
    def digest(self) -> bytes:
        return _h(_POLICY_SET_DOMAIN, self.compact_bytes)

    def policy_for(self, participant_index: int) -> SignedSplitScalarWitnessPolicy:
        index = int(participant_index)
        if not 0 <= index < len(self.policies):
            raise SplitScalarAuthorizationError("participant is absent from policy set")
        policy = self.policies[index]
        if policy.participant_index != index:  # pragma: no cover - constructor defense
            raise SplitScalarAuthorizationError("policy-set participant order drifted")
        return policy

    def verify(
        self,
        *,
        bundle: SignedSplitScalarBundle,
        plan: AuthorizationTransactionPlan,
    ) -> bool:
        try:
            if len(self.policies) != len(bundle.unsigned.contributions):
                return False
            common = self.unsigned.encoded
            return bool(
                bundle.verify_signatures()
                and all(policy.unsigned.encoded == common for policy in self.policies)
                and all(
                    policy.verify(bundle=bundle, plan=plan)
                    for policy in self.policies
                )
            )
        except Exception:
            return False

    @classmethod
    def assemble(
        cls,
        policies: Iterable[SignedSplitScalarWitnessPolicy],
        *,
        bundle: SignedSplitScalarBundle,
        plan: AuthorizationTransactionPlan,
    ) -> "SplitScalarWitnessPolicySet":
        rows = tuple(policies)
        if len(rows) != len(bundle.unsigned.contributions):
            raise SplitScalarAuthorizationError(
                "one common-policy signature per split-scalar participant is required"
            )
        by_index: dict[int, SignedSplitScalarWitnessPolicy] = {}
        for policy in rows:
            index = int(policy.participant_index)
            if index in by_index:
                raise SplitScalarAuthorizationError("duplicate participant witness policy")
            by_index[index] = policy
        if set(by_index) != set(range(len(bundle.unsigned.contributions))):
            raise SplitScalarAuthorizationError("participant witness-policy set is incomplete")
        result = cls(tuple(by_index[index] for index in range(len(by_index))))
        if not result.verify(bundle=bundle, plan=plan):
            raise SplitScalarAuthorizationError(
                "split-scalar witness-policy set failed verification"
            )
        return result

    @classmethod
    def parse_compact(cls, raw: bytes) -> "SplitScalarWitnessPolicySet":
        encoded = bytes(raw)
        if len(encoded) < 10 or encoded[:8] != _MAGIC_SET:
            raise SplitScalarAuthorizationError(
                "invalid split-scalar witness-policy-set framing"
            )
        count = int.from_bytes(encoded[8:10], "big")
        cursor = 10
        rows: list[SignedSplitScalarWitnessPolicy] = []
        for _ in range(count):
            if cursor + 4 > len(encoded):
                raise SplitScalarAuthorizationError(
                    "truncated split-scalar witness-policy-set length"
                )
            length = int.from_bytes(encoded[cursor : cursor + 4], "big")
            cursor += 4
            if length == 0 or cursor + length > len(encoded):
                raise SplitScalarAuthorizationError(
                    "invalid split-scalar participant-policy length"
                )
            rows.append(
                SignedSplitScalarWitnessPolicy.parse_compact(
                    encoded[cursor : cursor + length]
                )
            )
            cursor += length
        if cursor != len(encoded):
            raise SplitScalarAuthorizationError(
                "trailing bytes in split-scalar witness-policy set"
            )
        result = cls(tuple(rows))
        if result.compact_bytes != encoded:
            raise SplitScalarAuthorizationError(
                "non-canonical split-scalar witness-policy set"
            )
        return result


def derive_split_scalar_witness_selection(
    raw_transaction: bytes,
    *,
    policy: SignedSplitScalarWitnessPolicy,
    bundle: SignedSplitScalarBundle,
    plan: AuthorizationTransactionPlan,
) -> BitcoinWitnessSelection:
    if not policy.verify(bundle=bundle, plan=plan):
        raise SplitScalarAuthorizationError("split-scalar witness policy failed verification")
    slot = policy.unsigned.slot_id
    if not plan.verify_raw_transaction(slot, raw_transaction):
        raise SplitScalarAuthorizationError("transaction differs from precommitted stripped plan")
    try:
        return derive_unsigned_witness_selection(raw_transaction, unsigned=policy.unsigned)
    except Exception as exc:
        raise SplitScalarAuthorizationError(f"Bitcoin witness selection failed: {exc}") from exc


@dataclass(slots=True)
class SplitScalarParticipantReleaseSidecar:
    """One scalar-share holder's crash-durable release service."""

    bundle: SignedSplitScalarBundle
    participant_index: int
    retained_object_bytes: bytes
    required_manifest_pubkeys: tuple[bytes, ...]
    context: EvaluationContext
    plan: AuthorizationTransactionPlan
    witness_policy_set: SplitScalarWitnessPolicySet
    tree: LabelCommitmentTree
    participant_secret: int
    ledger: DurableSlotLedger
    rollback_witnesses: tuple[RollbackWitnessClient, ...]
    bitcoin_core: BitcoinCoreReader
    minimum_confirmations: int

    def __post_init__(self) -> None:
        index = int(self.participant_index)
        if not self.bundle.verify_signatures() or index >= len(self.bundle.unsigned.contributions):
            raise SplitScalarAuthorizationError("split-scalar bundle failed verification")
        contribution = self.bundle.unsigned.contributions[index]
        if public_key(self.participant_secret) != contribution.participant_pubkey:
            raise SplitScalarAuthorizationError("participant release secret does not match bundle")
        retained_raw = bytes(self.retained_object_bytes)
        if (
            len(retained_raw) != contribution.retained_object_bytes
            or sha256(retained_raw).digest() != contribution.retained_object_digest
        ):
            raise SplitScalarAuthorizationError("retained object does not match contribution")
        try:
            retained = parse_sealed_retained_object(retained_raw)
        except Exception as exc:
            raise SplitScalarAuthorizationError(f"retained object parsing failed: {exc}") from exc
        if not retained.manifest.verify(
            required_pubkeys=self.required_manifest_pubkeys,
            expected_context_digest=self.context.digest,
        ):
            raise SplitScalarAuthorizationError("retained-object manifest failed verification")
        slot = int(self.tree.slot_id)
        if not 0 <= slot < len(retained.slots):
            raise SplitScalarAuthorizationError("tree slot is absent from retained object")
        descriptor = retained.manifest.unsigned.slots[slot]
        if (
            descriptor.slot_id != slot
            or descriptor.input_label_root != self.tree.root
            or self.tree.context_digest != self.context.digest
            or self.tree.input_bits != self.witness_policy.unsigned.input_bits
        ):
            raise SplitScalarAuthorizationError("tree does not match retained slot")
        if self.bundle.unsigned.context_digest != self.context.digest:
            raise SplitScalarAuthorizationError("bundle and evaluation context differ")
        if self.ledger.context_digest != self.context.digest:
            raise SplitScalarAuthorizationError("durable ledger is for another context")
        if not self.witness_policy_set.verify(bundle=self.bundle, plan=self.plan):
            raise SplitScalarAuthorizationError("split-scalar witness-policy set failed verification")
        policy = self.witness_policy_set.policy_for(index)
        if policy.unsigned.slot_id != slot:
            raise SplitScalarAuthorizationError("witness policy is for another slot")
        if self.tree.input_bits != policy.unsigned.input_bits:
            raise SplitScalarAuthorizationError("selector width and participant label width differ")
        if self.plan.chain_genesis_hash != self.context.chain_genesis_hash:
            raise SplitScalarAuthorizationError("transaction plan is for another Bitcoin chain")
        if int(self.minimum_confirmations) < int(policy.minimum_confirmations):
            raise SplitScalarAuthorizationError(
                "configured confirmation depth is below the signed split-scalar minimum"
            )
        try:
            require_rollback_witness_set(
                self.rollback_witnesses,
                expected_digest=policy.rollback_witness_set_digest,
            )
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            raise SplitScalarAuthorizationError(
                f"rollback-witness bootstrap failed: {exc}"
            ) from exc

    @property
    def slot_id(self) -> int:
        return int(self.tree.slot_id)

    @property
    def witness_policy(self) -> SignedSplitScalarWitnessPolicy:
        return self.witness_policy_set.policy_for(self.participant_index)

    def issue(
        self,
        *,
        raw_transaction: bytes,
        block_hash: str,
        output_path: str | os.PathLike[str],
    ) -> tuple[
        AuthorizedLabelRelease,
        ConfirmedBitcoinObservation,
        tuple[RollbackWitnessReceipt, ...],
        bool,
    ]:
        selection = derive_split_scalar_witness_selection(
            raw_transaction,
            policy=self.witness_policy,
            bundle=self.bundle,
            plan=self.plan,
        )
        binding = BitcoinAuthorizationBinding.from_raw_transaction(
            raw_transaction,
            chain_genesis_hash=self.plan.chain_genesis_hash,
            authorization_input_index=self.witness_policy.unsigned.authorization_input_index,
        )
        observation = verify_confirmed_bitcoin_binding(
            self.bitcoin_core,
            binding=binding,
            raw_transaction=raw_transaction,
            block_hash=block_hash,
            minimum_confirmations=self.minimum_confirmations,
        )

        input_digest = _h(_INPUT_DOMAIN, selection.point_encoding)
        authorization_digest = _h(
            _AUTH_DOMAIN,
            self.witness_policy_set.digest,
            self.witness_policy.digest,
            binding.digest,
        )
        chain_binding_digest = _h(
            _CHAIN_DOMAIN,
            self.plan.templates[self.slot_id].stripped_digest,
            binding.counterproof_wtxid,
            binding.witness_digest,
        )
        began = False
        try:
            use = self.ledger.begin(
                self.slot_id,
                context_digest=self.context.digest,
                input_digest=input_digest,
                authorization_digest=authorization_digest,
                chain_binding_digest=chain_binding_digest,
            )
            began = True
            if use.terminal and use.state != "success":
                raise SplitScalarAuthorizationError(
                    f"slot previously terminated as {use.state}"
                )
            self.ledger.record_chain_observation(
                self.slot_id,
                event_type="confirmed",
                block_hash=bytes.fromhex(observation.block_hash),
                height=observation.block_height,
            )
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant_secret,
                witnesses=self.rollback_witnesses,
            )

            final_observation = verify_confirmed_bitcoin_binding(
                self.bitcoin_core,
                binding=binding,
                raw_transaction=raw_transaction,
                block_hash=block_hash,
                minimum_confirmations=self.minimum_confirmations,
            )
            final_selection = derive_split_scalar_witness_selection(
                raw_transaction,
                policy=self.witness_policy,
                bundle=self.bundle,
                plan=self.plan,
            )
            if (
                final_selection.point_encoding != selection.point_encoding
                or final_observation.txid != observation.txid
                or final_observation.wtxid != observation.wtxid
                or final_observation.block_hash != observation.block_hash
                or final_observation.block_height != observation.block_height
            ):
                raise SplitScalarAuthorizationError(
                    "Bitcoin inclusion changed while authorizing participant release"
                )
            self.ledger.finalize(self.slot_id, outcome="success")
            receipts = anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant_secret,
                witnesses=self.rollback_witnesses,
            )
            release = issue_label_release(
                self.tree,
                point=decompress_g1(selection.point_encoding),
                # wtxid, not txid: this field binds the exact selector witness.
                authorization_txid=binding.counterproof_wtxid,
                authorizer_secret=self.participant_secret,
            )
            if (
                release.context_digest != self.context.digest
                or release.slot_id != self.slot_id
                or release.input_label_root != self.tree.root
                or release.point_encoding != selection.point_encoding
                or not release.verify_signature(
                    self.bundle.unsigned.contributions[self.participant_index].participant_pubkey
                )
            ):
                raise SplitScalarAuthorizationError("internally generated release failed verification")
            created = atomic_write_once(output_path, release.compact_bytes)
            return release, final_observation, receipts, created
        except Exception as exc:
            if began:
                try:
                    current = self.ledger.use(self.slot_id)
                    if current.state == "burned":
                        self.ledger.finalize(self.slot_id, outcome="abort")
                        anchor_ledger_at_all_witnesses(
                            self.ledger,
                            participant_secret=self.participant_secret,
                            witnesses=self.rollback_witnesses,
                        )
                except Exception:
                    pass
            if isinstance(exc, SplitScalarAuthorizationError):
                raise
            if isinstance(exc, (ReleaseSidecarError, RollbackWitnessError)):
                raise SplitScalarAuthorizationError(
                    f"split-scalar participant release failed: {exc}"
                ) from exc
            raise SplitScalarAuthorizationError(
                f"split-scalar participant recheck failed: {exc}"
            ) from exc
