from __future__ import annotations

"""Bind RankLock future-point labels to consensus-validated witness choices.

A signed off-chain request is not enough for a funded protocol: the point used
for label release must be derivable from the exact transaction witness accepted
by Bitcoin Core.  This module commits every selector position to two exact
witness-item hashes, plus the tapscript and control block.  The setup committee
signs the policy.  A release sidecar then derives the canonical BN254 point from
those witness choices and rejects any request whose point differs.

Each selector alternative is a one-time secret DFB input label.  The tapscript
hash-locks both alternatives at every position and accepts exactly one revealed
preimage.  Consequently, observing the selected witness labels lets a third
party copy the same point but does not let it change any bit under the same
precommitted transaction id.  Bitcoin Core remains the consensus oracle.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bip340 import BIP340Error, lift_x, sign, tapleaf_hash, verify
from .bitcoin_authorization import ParsedBitcoinTransaction, parse_bitcoin_transaction
from .bitcoin_tx import (
    SIGHASH_DEFAULT,
    TxOut,
    parse_transaction,
    taproot_script_path_sighash,
)
from .bn254_real import B, FIELD_MODULUS, FQ, affine, compress_g1, decompress_g1, is_on_curve
from .committee_authorization import (
    CommitteeAuthorizationRequest,
    SignedCommitteeActivation,
)


# v2 adds the mandatory request-authorizer key to the policy body.  The magic
# is bumped so a v1 policy (whose tapscript had no signature requirement) fails
# to parse loudly rather than being silently accepted under the new rules.
_MAGIC = b"RLWP2502"
_POLICY_DOMAIN = b"ranklock/bitcoin-witness-policy/v1\x00"
_POLICY_SIGN_DOMAIN = b"ranklock/bitcoin-witness-policy-sign/v1\x00"
_SCRIPT_DOMAIN = b"ranklock/bitcoin-witness-script/v1\x00"
_CONTROL_DOMAIN = b"ranklock/bitcoin-witness-control/v1\x00"
_SIG_BYTES = 64
_HASH_BYTES = 32
_SELECTOR = 1
_FIXED = 0
_RULE_BYTES = 68
# magic + context + activation + slot id + input index + input bits +
# tapscript hash + control-block hash + authorizer pubkey + rule count.
# Shared by both the unsigned and signed parsers so the two cannot drift.
_POLICY_FIXED_BYTES = 8 + 32 + 32 + 4 + 4 + 2 + 32 + 32 + 32 + 2


class BitcoinWitnessSelectionError(ValueError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise BitcoinWitnessSelectionError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _h(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        digest.update(bytes(part))
    return digest.digest()


def witness_item_hash(item: bytes) -> bytes:
    # Tapscript OP_SHA256 computes the untagged hash.  Context, slot and bit
    # separation are supplied by the signed policy and by independent labels.
    return sha256(bytes(item)).digest()


def witness_script_hash(script: bytes) -> bytes:
    return _h(_SCRIPT_DOMAIN, bytes(script))


def witness_control_hash(control: bytes) -> bytes:
    return _h(_CONTROL_DOMAIN, bytes(control))


@dataclass(frozen=True, slots=True)
class WitnessItemRule:
    """One witness argument rule before tapscript/control-block elements."""

    kind: int
    coordinate: int
    bit: int
    zero_hash: bytes
    one_hash: bytes
    schema: str = "ranklock-witness-item-rule-v1"

    def __post_init__(self) -> None:
        if self.kind not in {_FIXED, _SELECTOR}:
            raise BitcoinWitnessSelectionError("witness rule kind is invalid")
        if self.kind == _SELECTOR:
            if self.coordinate not in (0, 1):
                raise BitcoinWitnessSelectionError("selector coordinate must be 0 or 1")
            if not 0 <= int(self.bit) < 2**16:
                raise BitcoinWitnessSelectionError("selector bit does not fit u16")
            if bytes(self.zero_hash) == bytes(self.one_hash):
                raise BitcoinWitnessSelectionError("selector alternatives must be distinct")
        else:
            if self.coordinate != 0 or self.bit != 0:
                raise BitcoinWitnessSelectionError("fixed rule has nonzero selector metadata")
            if bytes(self.one_hash) != bytes(_HASH_BYTES):
                raise BitcoinWitnessSelectionError("fixed rule second hash must be zero")
        if len(bytes(self.zero_hash)) != _HASH_BYTES or len(bytes(self.one_hash)) != _HASH_BYTES:
            raise BitcoinWitnessSelectionError("witness rule hashes must be 32 bytes")

    @classmethod
    def selector(
        cls,
        *,
        coordinate: int,
        bit: int,
        zero_item: bytes,
        one_item: bytes,
    ) -> "WitnessItemRule":
        return cls(
            _SELECTOR,
            int(coordinate),
            int(bit),
            witness_item_hash(zero_item),
            witness_item_hash(one_item),
        )

    @classmethod
    def fixed(cls, item: bytes) -> "WitnessItemRule":
        return cls(_FIXED, 0, 0, witness_item_hash(item), bytes(_HASH_BYTES))

    @property
    def encoded(self) -> bytes:
        return (
            bytes((self.kind, self.coordinate))
            + _u(self.bit, 2, "selector bit")
            + bytes(self.zero_hash)
            + bytes(self.one_hash)
        )

    @classmethod
    def parse(cls, raw: bytes) -> "WitnessItemRule":
        raw = bytes(raw)
        if len(raw) != 68:
            raise BitcoinWitnessSelectionError("witness rule length mismatch")
        result = cls(
            raw[0],
            raw[1],
            int.from_bytes(raw[2:4], "big"),
            raw[4:36],
            raw[36:68],
        )
        if result.encoded != raw:
            raise BitcoinWitnessSelectionError("non-canonical witness rule")
        return result


def witness_rules_from_label_pairs(
    label_pairs: Sequence[tuple[bytes, bytes]],
    *,
    input_bits: int,
) -> tuple[WitnessItemRule, ...]:
    if len(label_pairs) != 2 * int(input_bits):
        raise BitcoinWitnessSelectionError("label-pair count does not match input width")
    rules: list[WitnessItemRule] = []
    for flat_index, pair in enumerate(label_pairs):
        coordinate, bit = divmod(flat_index, int(input_bits))
        zero, one = bytes(pair[0]), bytes(pair[1])
        if len(zero) != 16 or len(one) != 16:
            raise BitcoinWitnessSelectionError("DFB witness labels must be 16 bytes")
        rules.append(
            WitnessItemRule.selector(
                coordinate=coordinate,
                bit=bit,
                zero_item=zero,
                one_item=one,
            )
        )
    return tuple(rules)


def selector_validation_tapscript(
    rules: Sequence[WitnessItemRule],
    *,
    authorizer_pubkey: bytes,
) -> bytes:
    """Build a tapscript that validates every secret selector preimage.

    Witness elements are consumed from the top of the stack, so rules are
    emitted in reverse while the policy/witness remains coordinate-major.
    Tapscript removes the legacy script-size and non-push-opcode limits; the
    512-item construction remains bounded by transaction weight and the 1000
    initial-stack-element limit.

    The script opens with ``OP_CHECKSIGVERIFY`` against the request
    authorizer's x-only key.  Hash-locking the labels alone is not sufficient
    for a funded protocol: the selected labels become public the moment the
    authorization transaction is broadcast, so a script that only checks label
    preimages lets any observer re-spend the same input in a transaction with
    different outputs or fee.  Requiring a BIP340 signature over the exact
    BIP341 sighash binds the spend to the precommitted outputs, amounts,
    sequences, version and locktime, so revealed labels are not a reusable
    spending capability.  The signature is the topmost witness item and is
    therefore checked before any of the 512 hash comparisons run.
    """

    pubkey = bytes(authorizer_pubkey)
    if len(pubkey) != 32:
        raise BitcoinWitnessSelectionError(
            "authorizer public key must be a 32-byte BIP340 x-only key"
        )

    script = bytearray()
    # PUSH32(authorizer pubkey) OP_CHECKSIGVERIFY
    script.extend(b"\x20" + pubkey + b"\xad")
    for rule in reversed(tuple(rules)):
        if rule.kind == _FIXED:
            # OP_SHA256 PUSH32(hash) OP_EQUALVERIFY
            script.extend(b"\xa8\x20" + bytes(rule.zero_hash) + b"\x88")
            continue
        # OP_DUP OP_SHA256 PUSH32(h0) OP_EQUAL OP_SWAP OP_SHA256
        # PUSH32(h1) OP_EQUAL OP_BOOLOR OP_VERIFY
        script.extend(
            b"\x76\xa8\x20"
            + bytes(rule.zero_hash)
            + b"\x87\x7c\xa8\x20"
            + bytes(rule.one_hash)
            + b"\x87\x9b\x69"
        )
    script.extend(b"\x51")  # OP_TRUE: exactly one true stack element remains.
    return bytes(script)


def authorization_sighash(
    raw_transaction: bytes,
    *,
    authorization_input_index: int,
    spent_values_sat: Sequence[int],
    spent_scripts: Sequence[bytes],
    tapscript: bytes,
) -> bytes:
    """Return the BIP341 script-path sighash the authorizer must sign.

    The message commits to the transaction version, locktime, every input
    outpoint and sequence, every spent amount and scriptPubKey, and every
    output.  Consequently the fee (inputs minus outputs) is committed too, so
    a third party holding the revealed labels cannot redirect value, change
    the fee, or replace the transaction under BIP125.
    """

    transaction = parse_transaction(bytes(raw_transaction))
    values = tuple(int(value) for value in spent_values_sat)
    scripts = tuple(bytes(script) for script in spent_scripts)
    if len(values) != len(scripts):
        raise BitcoinWitnessSelectionError(
            "spent value and script counts differ"
        )
    if len(values) != len(transaction.inputs):
        raise BitcoinWitnessSelectionError(
            "one spent output is required for every transaction input"
        )
    spent_outputs = tuple(
        TxOut(value=value, script_pubkey=script)
        for value, script in zip(values, scripts, strict=True)
    )
    return taproot_script_path_sighash(
        transaction,
        input_index=int(authorization_input_index),
        spent_outputs=spent_outputs,
        tapleaf_hash=tapleaf_hash(bytes(tapscript)),
        hash_type=SIGHASH_DEFAULT,
    )


def sign_authorization_witness(
    raw_transaction: bytes,
    *,
    authorization_input_index: int,
    spent_values_sat: Sequence[int],
    spent_scripts: Sequence[bytes],
    tapscript: bytes,
    request_authorizer_secret: int,
    aux_rand: bytes | None = None,
) -> bytes:
    """Sign the exact authorization transaction with the request authorizer key.

    The signature is over :func:`authorization_sighash`, so it is only valid
    for this exact precommitted transaction.  ``aux_rand=None`` keeps the
    deterministic BIP340 mode used by the rest of the research code; a
    production signer should supply independent randomness.
    """

    message = authorization_sighash(
        raw_transaction,
        authorization_input_index=authorization_input_index,
        spent_values_sat=spent_values_sat,
        spent_scripts=spent_scripts,
        tapscript=tapscript,
    )
    return sign(message, int(request_authorizer_secret), aux_rand)


@dataclass(frozen=True, slots=True)
class UnsignedBitcoinWitnessPolicy:
    context_digest: bytes
    activation_digest: bytes
    slot_id: int
    authorization_input_index: int
    input_bits: int
    tapscript_hash: bytes
    control_block_hash: bytes
    authorizer_pubkey: bytes
    rules: tuple[WitnessItemRule, ...]
    schema: str = "ranklock-unsigned-bitcoin-witness-policy-v2"

    def __post_init__(self) -> None:
        for value, name in (
            (self.context_digest, "context digest"),
            (self.activation_digest, "activation digest"),
            (self.tapscript_hash, "tapscript hash"),
            (self.control_block_hash, "control-block hash"),
            (self.authorizer_pubkey, "authorizer public key"),
        ):
            if len(bytes(value)) != _HASH_BYTES:
                raise BitcoinWitnessSelectionError(f"{name} must be 32 bytes")
        try:
            # An unliftable x-only key would make the committed tapleaf
            # permanently unspendable; reject it at policy-construction time
            # rather than after the funding output already exists.
            lift_x(int.from_bytes(bytes(self.authorizer_pubkey), "big"))
        except BIP340Error as exc:
            raise BitcoinWitnessSelectionError(
                "authorizer public key is not a valid secp256k1 x-only key"
            ) from exc
        if not 0 <= int(self.slot_id) < 2**32:
            raise BitcoinWitnessSelectionError("slot id does not fit u32")
        if not 0 <= int(self.authorization_input_index) < 2**32:
            raise BitcoinWitnessSelectionError("authorization input index does not fit u32")
        if not 1 < int(self.input_bits) < 2**16:
            raise BitcoinWitnessSelectionError("input bit width is invalid")
        if not self.rules or len(self.rules) >= 2**16:
            raise BitcoinWitnessSelectionError("witness rule count is invalid")
        selectors = {
            (rule.coordinate, rule.bit)
            for rule in self.rules
            if rule.kind == _SELECTOR
        }
        selector_order = tuple(
            (rule.coordinate, rule.bit)
            for rule in self.rules
            if rule.kind == _SELECTOR
        )
        expected_order = tuple(
            (coordinate, bit)
            for coordinate in (0, 1)
            for bit in range(self.input_bits)
        )
        expected = {
            (coordinate, bit)
            for coordinate in (0, 1)
            for bit in range(self.input_bits)
        }
        if selectors != expected:
            raise BitcoinWitnessSelectionError(
                "selector rules must cover every coordinate bit exactly once"
            )
        if sum(rule.kind == _SELECTOR for rule in self.rules) != 2 * self.input_bits:
            raise BitcoinWitnessSelectionError("duplicate witness selector rule")
        if selector_order != expected_order:
            raise BitcoinWitnessSelectionError(
                "selector rules are not in canonical coordinate-major order"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _MAGIC
            + bytes(self.context_digest)
            + bytes(self.activation_digest)
            + _u(self.slot_id, 4, "slot id")
            + _u(self.authorization_input_index, 4, "authorization input index")
            + _u(self.input_bits, 2, "input bits")
            + bytes(self.tapscript_hash)
            + bytes(self.control_block_hash)
            + bytes(self.authorizer_pubkey)
            + _u(len(self.rules), 2, "witness rule count")
            + b"".join(rule.encoded for rule in self.rules)
        )

    @property
    def digest(self) -> bytes:
        return _h(_POLICY_DOMAIN, self.encoded)

    @property
    def signing_message(self) -> bytes:
        return _h(_POLICY_SIGN_DOMAIN, self.digest)

    @classmethod
    def parse(cls, raw: bytes) -> "UnsignedBitcoinWitnessPolicy":
        raw = bytes(raw)
        fixed = _POLICY_FIXED_BYTES
        if len(raw) < fixed or raw[:8] != _MAGIC:
            raise BitcoinWitnessSelectionError("invalid witness-policy framing")
        cursor = 8
        context = raw[cursor : cursor + 32]; cursor += 32
        activation = raw[cursor : cursor + 32]; cursor += 32
        slot_id = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        input_index = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        input_bits = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        script_hash = raw[cursor : cursor + 32]; cursor += 32
        control_hash = raw[cursor : cursor + 32]; cursor += 32
        authorizer_pubkey = raw[cursor : cursor + 32]; cursor += 32
        count = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        if len(raw) != fixed + count * _RULE_BYTES:
            raise BitcoinWitnessSelectionError("witness-policy length mismatch")
        rules = tuple(
            WitnessItemRule.parse(
                raw[cursor + _RULE_BYTES * i : cursor + _RULE_BYTES * (i + 1)]
            )
            for i in range(count)
        )
        result = cls(
            context,
            activation,
            slot_id,
            input_index,
            input_bits,
            script_hash,
            control_hash,
            authorizer_pubkey,
            rules,
        )
        if result.encoded != raw:
            raise BitcoinWitnessSelectionError("non-canonical witness policy")
        return result


@dataclass(frozen=True, slots=True)
class SignedBitcoinWitnessPolicy:
    unsigned: UnsignedBitcoinWitnessPolicy
    participant_signatures: tuple[bytes, ...]
    schema: str = "ranklock-signed-bitcoin-witness-policy-v1"

    def __post_init__(self) -> None:
        if len(self.participant_signatures) < 2:
            raise BitcoinWitnessSelectionError("witness policy needs at least two signatures")
        if any(len(bytes(signature)) != _SIG_BYTES for signature in self.participant_signatures):
            raise BitcoinWitnessSelectionError("witness-policy signatures must be 64 bytes")

    def verify(self, activation: SignedCommitteeActivation) -> bool:
        participants = activation.unsigned.participants
        unsigned = self.unsigned
        return bool(
            activation.verify()
            and unsigned.context_digest == activation.unsigned.context_digest
            and unsigned.activation_digest == activation.digest
            and unsigned.slot_id == activation.unsigned.slot_id
            and unsigned.input_bits == activation.unsigned.input_bits
            and len(self.participant_signatures) == len(participants)
            and all(
                verify(
                    unsigned.signing_message,
                    descriptor.participant_pubkey,
                    signature,
                )
                for descriptor, signature in zip(
                    participants, self.participant_signatures, strict=True
                )
            )
        )

    @property
    def compact_bytes(self) -> bytes:
        return (
            self.unsigned.encoded
            + _u(len(self.participant_signatures), 2, "signature count")
            + b"".join(bytes(signature) for signature in self.participant_signatures)
        )

    @classmethod
    def create(
        cls,
        unsigned: UnsignedBitcoinWitnessPolicy,
        *,
        activation: SignedCommitteeActivation,
        participant_secrets: Sequence[int],
    ) -> "SignedBitcoinWitnessPolicy":
        if len(participant_secrets) != len(activation.unsigned.participants):
            raise BitcoinWitnessSelectionError("participant secret count mismatch")
        candidate = cls(
            unsigned,
            tuple(sign(unsigned.signing_message, int(secret)) for secret in participant_secrets),
        )
        if not candidate.verify(activation):
            raise BitcoinWitnessSelectionError("witness-policy participant keys mismatch")
        return candidate

    @classmethod
    def parse_compact(cls, raw: bytes) -> "SignedBitcoinWitnessPolicy":
        raw = bytes(raw)
        unsigned_fixed = _POLICY_FIXED_BYTES
        if len(raw) < unsigned_fixed + 2 or raw[:8] != _MAGIC:
            raise BitcoinWitnessSelectionError("invalid signed witness-policy framing")
        count = int.from_bytes(raw[unsigned_fixed - 2 : unsigned_fixed], "big")
        unsigned_len = unsigned_fixed + _RULE_BYTES * count
        if len(raw) < unsigned_len + 2:
            raise BitcoinWitnessSelectionError("truncated signed witness policy")
        unsigned = UnsignedBitcoinWitnessPolicy.parse(raw[:unsigned_len])
        sig_count = int.from_bytes(raw[unsigned_len : unsigned_len + 2], "big")
        if len(raw) != unsigned_len + 2 + sig_count * _SIG_BYTES:
            raise BitcoinWitnessSelectionError("signed witness-policy length mismatch")
        signatures = tuple(
            raw[unsigned_len + 2 + _SIG_BYTES * i : unsigned_len + 2 + _SIG_BYTES * (i + 1)]
            for i in range(sig_count)
        )
        result = cls(unsigned, signatures)
        if result.compact_bytes != raw:
            raise BitcoinWitnessSelectionError("non-canonical signed witness policy")
        return result


@dataclass(frozen=True, slots=True)
class BitcoinWitnessSelection:
    point_encoding: bytes
    x: int
    y: int
    selected_bits: tuple[int, ...]
    transaction: ParsedBitcoinTransaction
    schema: str = "ranklock-bitcoin-witness-selection-v1"


def derive_unsigned_witness_selection(
    raw_transaction: bytes,
    *,
    unsigned: UnsignedBitcoinWitnessPolicy,
) -> BitcoinWitnessSelection:
    """Derive the canonical point from one already-authenticated policy body.

    Protocol-specific callers must authenticate ``unsigned`` before invoking
    this function.  Keeping the consensus/witness decoder independent of the
    committee signature wrapper lets the split-scalar safety mode reuse the
    exact same parser and selector semantics without pretending that a
    one-party scalar-share policy is a committee activation.
    """

    parsed = parse_bitcoin_transaction(raw_transaction)
    index = unsigned.authorization_input_index
    if index >= len(parsed.witness_stacks):
        raise BitcoinWitnessSelectionError("authorization witness input is absent")
    stack = parsed.witness_stacks[index]
    if stack and stack[-1][:1] == b"\x50":
        raise BitcoinWitnessSelectionError("Taproot annexes are forbidden by RankLock policy")
    # Layout: selector items, then the authorizer signature, then the
    # tapscript and control block.  The signature is topmost so the script's
    # leading OP_CHECKSIGVERIFY runs before any label hashing.
    if len(stack) != len(unsigned.rules) + 3:
        raise BitcoinWitnessSelectionError("witness stack does not match policy layout")
    script, control = stack[-2], stack[-1]
    authorizer_signature = stack[-3]
    if len(authorizer_signature) != _SIG_BYTES:
        # RankLock mandates SIGHASH_DEFAULT, whose BIP341 signature is exactly
        # 64 bytes.  A 65-byte signature carries an explicit sighash flag and
        # would let a spender re-scope what the signature commits to.
        raise BitcoinWitnessSelectionError(
            "authorization witness signature must be 64 bytes (SIGHASH_DEFAULT)"
        )
    if witness_script_hash(script) != unsigned.tapscript_hash:
        raise BitcoinWitnessSelectionError("witness tapscript differs from signed policy")
    if witness_control_hash(control) != unsigned.control_block_hash:
        raise BitcoinWitnessSelectionError("witness control block differs from signed policy")
    if len(control) < 33 or (len(control) - 33) % 32 != 0 or len(control) > 33 + 128 * 32:
        raise BitcoinWitnessSelectionError("Taproot control block length is invalid")
    if control[0] & 0xFE != 0xC0:
        raise BitcoinWitnessSelectionError("witness policy requires a BIP342 tapscript leaf")

    coordinates = [0, 0]
    selected: list[int] = []
    seen: set[tuple[int, int]] = set()
    for item, rule in zip(stack[:-3], unsigned.rules, strict=True):
        digest = witness_item_hash(item)
        if rule.kind == _FIXED:
            if digest != rule.zero_hash:
                raise BitcoinWitnessSelectionError("fixed witness item differs from signed policy")
            continue
        if digest == rule.zero_hash:
            value = 0
        elif digest == rule.one_hash:
            value = 1
        else:
            raise BitcoinWitnessSelectionError("selector witness item is neither authorized alternative")
        key = (rule.coordinate, rule.bit)
        if key in seen:  # guarded by policy construction, retained for parse defense
            raise BitcoinWitnessSelectionError("duplicate selector bit")
        seen.add(key)
        coordinates[rule.coordinate] |= value << rule.bit
        selected.append(value)

    x, y = coordinates
    try:
        if x >= FIELD_MODULUS or y >= FIELD_MODULUS:
            raise ValueError("coordinate is outside BN254 base field")
        point = (FQ(x), FQ(y), FQ.one())
        if not is_on_curve(point, B):
            raise ValueError("coordinate pair is off curve")
        point_encoding = compress_g1(point)
        reparsed = decompress_g1(point_encoding)
        affine_point = affine(reparsed)
    except Exception as exc:
        raise BitcoinWitnessSelectionError("witness bits do not encode a canonical BN254 point") from exc
    if affine_point is None or (int(affine_point[0].n), int(affine_point[1].n)) != (x, y):
        raise BitcoinWitnessSelectionError("witness x/y bits are not one canonical BN254 point")
    return BitcoinWitnessSelection(
        point_encoding=point_encoding,
        x=x,
        y=y,
        selected_bits=tuple(selected),
        transaction=parsed,
    )


def derive_witness_selection(
    raw_transaction: bytes,
    *,
    policy: SignedBitcoinWitnessPolicy,
    activation: SignedCommitteeActivation,
) -> BitcoinWitnessSelection:
    if not policy.verify(activation):
        raise BitcoinWitnessSelectionError("witness policy failed committee verification")
    return derive_unsigned_witness_selection(raw_transaction, unsigned=policy.unsigned)


def verify_request_matches_witness(
    request: CommitteeAuthorizationRequest,
    *,
    raw_transaction: bytes,
    policy: SignedBitcoinWitnessPolicy,
    activation: SignedCommitteeActivation,
) -> BitcoinWitnessSelection:
    if not request.verify(activation):
        raise BitcoinWitnessSelectionError("committee request failed verification")
    if (
        policy.unsigned.authorization_input_index
        != request.bitcoin_binding.authorization_input_index
    ):
        raise BitcoinWitnessSelectionError(
            "witness policy and request bind different authorization inputs"
        )
    selection = derive_witness_selection(
        raw_transaction,
        policy=policy,
        activation=activation,
    )
    if selection.point_encoding != request.point_encoding:
        raise BitcoinWitnessSelectionError(
            "off-chain request point differs from consensus-confirmed witness selection"
        )
    if not request.bitcoin_binding.verify_raw_transaction(raw_transaction):
        raise BitcoinWitnessSelectionError("request binding differs from witness transaction")
    return selection


def execute_selector_tapscript_model(
    script: bytes,
    witness_items: Sequence[bytes],
    *,
    checksig_valid: bool = True,
) -> bool:
    """Execute the exact opcode subset emitted by
    :func:`selector_validation_tapscript`.

    This small independent model catches bytecode/stack-order regressions in
    the generated 512-selector script.  It is intentionally *not* a Bitcoin
    consensus implementation; the release gate still requires Bitcoin Core.
    Unsupported opcodes, malformed pushes, stack underflow, failed VERIFY, or a
    non-clean final stack return ``False``.

    ``checksig_valid`` stands in for the BIP340 verification the model cannot
    perform: it has no transaction, no sighash and no signing key.  The model
    still enforces the *stack mechanics* of ``OP_CHECKSIGVERIFY`` (a 32-byte
    key above a 64-byte signature), so a witness-ordering regression is caught
    here even though the cryptographic check itself belongs to Bitcoin Core.
    """

    code = bytes(script)
    stack = [bytes(item) for item in witness_items]

    def truth(value: bytes) -> bool:
        # The generated program only creates empty/01 booleans.  Implement the
        # full Bitcoin negative-zero rule anyway to keep the model fail-closed.
        value = bytes(value)
        for index, byte in enumerate(value):
            if byte != 0:
                return not (index == len(value) - 1 and byte == 0x80)
        return False

    cursor = 0
    try:
        while cursor < len(code):
            opcode = code[cursor]
            cursor += 1
            if 1 <= opcode <= 75:
                if cursor + opcode > len(code):
                    return False
                stack.append(code[cursor : cursor + opcode])
                cursor += opcode
            elif opcode == 0x51:  # OP_1 / OP_TRUE
                stack.append(b"\x01")
            elif opcode == 0x69:  # OP_VERIFY
                if not stack or not truth(stack.pop()):
                    return False
            elif opcode == 0x76:  # OP_DUP
                if not stack:
                    return False
                stack.append(stack[-1])
            elif opcode == 0x7C:  # OP_SWAP
                if len(stack) < 2:
                    return False
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif opcode == 0x87:  # OP_EQUAL
                if len(stack) < 2:
                    return False
                right = stack.pop()
                left = stack.pop()
                stack.append(b"\x01" if left == right else b"")
            elif opcode == 0x88:  # OP_EQUALVERIFY
                if len(stack) < 2:
                    return False
                right = stack.pop()
                left = stack.pop()
                if left != right:
                    return False
            elif opcode == 0x9B:  # OP_BOOLOR
                if len(stack) < 2:
                    return False
                right = truth(stack.pop())
                left = truth(stack.pop())
                stack.append(b"\x01" if left or right else b"")
            elif opcode == 0xA8:  # OP_SHA256
                if not stack:
                    return False
                stack.append(sha256(stack.pop()).digest())
            elif opcode == 0xAD:  # OP_CHECKSIGVERIFY
                if len(stack) < 2:
                    return False
                pubkey = stack.pop()
                signature = stack.pop()
                if len(pubkey) != _HASH_BYTES or len(signature) != _SIG_BYTES:
                    return False
                if not checksig_valid:
                    return False
            else:
                return False
    except Exception:
        return False
    return len(stack) == 1 and truth(stack[0])
