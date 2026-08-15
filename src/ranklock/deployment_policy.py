from __future__ import annotations

"""Fail-closed deployment and funds-safety qualification.

The cryptographic implementation must never infer "safe for funds" from a test
report or a command-line flag.  Enforce mode is enabled only by a governance-
signed policy, a matching immutable software/artifact subject, live runtime
facts, and unexpired role-specific attestations from explicitly authorized and
independent keys.

This gate does not make an implementation secure.  It makes unresolved gates
operationally non-bypassable in the reference deployment.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Mapping, Sequence

from .bip340 import public_key, sign, verify


_HASH = 32
_SIG = 64
_ZERO = bytes(_HASH)
_SUBJECT_MAGIC = b"RLSJ2501"
_POLICY_MAGIC = b"RLFS2512"
_ATTEST_MAGIC = b"RLSA2501"
_SUBJECT_DOMAIN = b"ranklock/safety-subject/v1\x00"
_POLICY_DOMAIN = b"ranklock/funds-policy/v3\x00"
_POLICY_SIGN_DOMAIN = b"ranklock/funds-policy-sign/v3\x00"
_ATTEST_DOMAIN = b"ranklock/security-attestation/v1\x00"
_ATTEST_SIGN_DOMAIN = b"ranklock/security-attestation-sign/v1\x00"

ROLE_ACTIVE_MPC = "active-mpc"
ROLE_SPLIT_SCALAR_SETUP = "split-scalar-one-honest-setup"
ROLE_BITCOIN_CORE_REGTEST = "bitcoin-core-regtest"
ROLE_BRIDGE_INTEGRATION = "bridge-integration"
ROLE_CONSTANT_TIME = "constant-time-hardening"
ROLE_CRYPTO_AUDIT = "independent-cryptography-audit"
ROLE_IMPLEMENTATION_AUDIT = "independent-implementation-audit"
ROLE_OPERATIONS = "operations-and-recovery"

COMMON_PRODUCTION_ROLES = (
    ROLE_BITCOIN_CORE_REGTEST,
    ROLE_BRIDGE_INTEGRATION,
    ROLE_CONSTANT_TIME,
    ROLE_CRYPTO_AUDIT,
    ROLE_IMPLEMENTATION_AUDIT,
    ROLE_OPERATIONS,
)
PRODUCTION_ROLES = (ROLE_ACTIVE_MPC,) + COMMON_PRODUCTION_ROLES
SETUP_SECURITY_MODES = {"active-mpc": 0, "split-scalar-n-of-n": 1}
CODE_SETUP_SECURITY_MODES = {value: key for key, value in SETUP_SECURITY_MODES.items()}


def production_roles_for_mode(setup_security_mode: str) -> tuple[str, ...]:
    if setup_security_mode == "active-mpc":
        return (ROLE_ACTIVE_MPC,) + COMMON_PRODUCTION_ROLES
    if setup_security_mode == "split-scalar-n-of-n":
        return (ROLE_SPLIT_SCALAR_SETUP,) + COMMON_PRODUCTION_ROLES
    raise DeploymentPolicyError("unknown setup security mode")
INDEPENDENT_ROLES = frozenset({ROLE_CRYPTO_AUDIT, ROLE_IMPLEMENTATION_AUDIT})
NETWORK_CODES = {"regtest": 0, "signet": 1, "testnet": 2, "mainnet": 3}
CODE_NETWORKS = {value: key for key, value in NETWORK_CODES.items()}
DEPLOYMENT_MODES = {"observe", "canary", "enforce"}


class DeploymentPolicyError(ValueError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise DeploymentPolicyError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _lp(value: bytes, *, width: int = 2) -> bytes:
    return _u(len(value), width, "length") + bytes(value)


def _h(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        digest.update(bytes(part))
    return digest.digest()


def _digest(value: bytes, name: str) -> bytes:
    value = bytes(value)
    if len(value) != _HASH:
        raise DeploymentPolicyError(f"{name} must be 32 bytes")
    return value


def _role(value: str) -> str:
    value = str(value)
    encoded = value.encode("ascii", "strict")
    if not 1 <= len(encoded) <= 64 or value.strip() != value:
        raise DeploymentPolicyError("security role is malformed")
    return value


@dataclass(frozen=True, slots=True)
class SafetySubject:
    version: str
    source_archive_sha256: bytes
    source_manifest_sha256: bytes
    retained_object_sha256: bytes
    retained_manifest_digest: bytes
    generator_code_hash: bytes
    bridge_commit: bytes
    context_digest: bytes
    schema: str = "ranklock-safety-subject-v1"

    def __post_init__(self) -> None:
        version = self.version.encode("ascii", "strict")
        if not 1 <= len(version) <= 64:
            raise DeploymentPolicyError("subject version is malformed")
        for field, name in (
            (self.source_archive_sha256, "source archive hash"),
            (self.source_manifest_sha256, "source manifest hash"),
            (self.retained_object_sha256, "retained object hash"),
            (self.retained_manifest_digest, "retained manifest digest"),
            (self.generator_code_hash, "generator code hash"),
            (self.bridge_commit, "bridge commit"),
            (self.context_digest, "context digest"),
        ):
            _digest(field, name)

    @property
    def encoded(self) -> bytes:
        return (
            _SUBJECT_MAGIC
            + _lp(self.version.encode("ascii"), width=1)
            + bytes(self.source_archive_sha256)
            + bytes(self.source_manifest_sha256)
            + bytes(self.retained_object_sha256)
            + bytes(self.retained_manifest_digest)
            + bytes(self.generator_code_hash)
            + bytes(self.bridge_commit)
            + bytes(self.context_digest)
        )

    @property
    def digest(self) -> bytes:
        return _h(_SUBJECT_DOMAIN, self.encoded)


@dataclass(frozen=True, slots=True)
class RoleAuthority:
    role: str
    minimum_signatures: int
    authorized_pubkeys: tuple[bytes, ...]
    schema: str = "ranklock-role-authority-v1"

    def __post_init__(self) -> None:
        _role(self.role)
        if not self.authorized_pubkeys:
            raise DeploymentPolicyError("role authority set is empty")
        if tuple(sorted(self.authorized_pubkeys)) != self.authorized_pubkeys:
            raise DeploymentPolicyError("role authority keys are not canonical")
        if len(set(self.authorized_pubkeys)) != len(self.authorized_pubkeys):
            raise DeploymentPolicyError("role authority keys are duplicated")
        if any(len(bytes(key)) != _HASH for key in self.authorized_pubkeys):
            raise DeploymentPolicyError("role authority key must be 32 bytes")
        if not 1 <= int(self.minimum_signatures) <= len(self.authorized_pubkeys):
            raise DeploymentPolicyError("role signature threshold is invalid")

    @property
    def encoded(self) -> bytes:
        role = self.role.encode("ascii")
        return (
            _lp(role, width=1)
            + _u(self.minimum_signatures, 2, "role threshold")
            + _u(len(self.authorized_pubkeys), 2, "role authority count")
            + b"".join(bytes(key) for key in self.authorized_pubkeys)
        )


@dataclass(frozen=True, slots=True)
class UnsignedFundsSafetyPolicy:
    subject_digest: bytes
    network: str
    chain_genesis_hash: bytes
    maximum_value_sat: int
    minimum_committee_members: int
    minimum_rollback_witnesses: int
    minimum_confirmations: int
    rollback_witness_pubkeys: tuple[bytes, ...]
    setup_participant_pubkeys: tuple[bytes, ...]
    governance_pubkeys: tuple[bytes, ...]
    governance_threshold: int
    role_authorities: tuple[RoleAuthority, ...]
    setup_security_mode: str = "active-mpc"
    schema: str = "ranklock-unsigned-funds-safety-policy-v4"

    def __post_init__(self) -> None:
        _digest(self.subject_digest, "subject digest")
        _digest(self.chain_genesis_hash, "chain genesis hash")
        if self.network not in NETWORK_CODES:
            raise DeploymentPolicyError("unknown Bitcoin network")
        if self.setup_security_mode not in SETUP_SECURITY_MODES:
            raise DeploymentPolicyError("unknown setup security mode")
        if not 0 <= int(self.maximum_value_sat) < 2**64:
            raise DeploymentPolicyError("maximum value does not fit u64")
        if not 2 <= int(self.minimum_committee_members) < 2**16:
            raise DeploymentPolicyError("minimum committee size is invalid")
        if not 1 <= int(self.minimum_rollback_witnesses) < 2**16:
            raise DeploymentPolicyError("minimum rollback-witness count is invalid")
        if not 1 <= int(self.minimum_confirmations) < 2**16:
            raise DeploymentPolicyError("minimum confirmation depth is invalid")
        for keys, name in (
            (self.rollback_witness_pubkeys, "rollback witness"),
            (self.setup_participant_pubkeys, "setup participant"),
            (self.governance_pubkeys, "governance"),
        ):
            if tuple(sorted(keys)) != keys or len(set(keys)) != len(keys):
                raise DeploymentPolicyError(f"{name} keys are not canonical and unique")
            if any(len(bytes(key)) != _HASH for key in keys):
                raise DeploymentPolicyError(f"{name} key must be 32 bytes")
        if len(self.rollback_witness_pubkeys) < self.minimum_rollback_witnesses:
            raise DeploymentPolicyError("rollback witness set is below signed minimum")
        if len(self.setup_participant_pubkeys) < self.minimum_committee_members:
            raise DeploymentPolicyError("setup participant set is below committee minimum")
        if not self.governance_pubkeys:
            raise DeploymentPolicyError("governance key set is empty")
        if not 1 <= int(self.governance_threshold) <= len(self.governance_pubkeys):
            raise DeploymentPolicyError("governance threshold is invalid")
        roles = tuple(authority.role for authority in self.role_authorities)
        if roles != tuple(sorted(roles)) or len(set(roles)) != len(roles):
            raise DeploymentPolicyError("role authorities are not canonical and unique")
        required_roles = production_roles_for_mode(self.setup_security_mode)
        if set(roles) != set(required_roles):
            raise DeploymentPolicyError("production policy must define every required role for its setup mode")
        rollback_keys = set(self.rollback_witness_pubkeys)
        setup_keys = set(self.setup_participant_pubkeys)
        governance_keys = set(self.governance_pubkeys)
        authority_by_role = {
            authority.role: set(authority.authorized_pubkeys)
            for authority in self.role_authorities
        }
        all_authority_keys = set().union(*authority_by_role.values())
        if (
            rollback_keys.intersection(setup_keys)
            or rollback_keys.intersection(governance_keys)
            or rollback_keys.intersection(all_authority_keys)
        ):
            raise DeploymentPolicyError(
                "rollback witness identities must be independent of setup, governance, and attestation authorities"
            )
        non_audit_role_keys = set().union(
            *(
                keys
                for role, keys in authority_by_role.items()
                if role not in INDEPENDENT_ROLES
            )
        )
        for authority in self.role_authorities:
            if authority.role in INDEPENDENT_ROLES and (
                setup_keys.intersection(authority.authorized_pubkeys)
                or governance_keys.intersection(authority.authorized_pubkeys)
                or non_audit_role_keys.intersection(authority.authorized_pubkeys)
            ):
                raise DeploymentPolicyError(
                    "independent audit authorities must be disjoint from setup, governance, and operational keys"
                )
        cryptography_auditors = authority_by_role[ROLE_CRYPTO_AUDIT]
        implementation_auditors = authority_by_role[ROLE_IMPLEMENTATION_AUDIT]
        if cryptography_auditors.intersection(implementation_auditors):
            raise DeploymentPolicyError(
                "cryptography and implementation audit authorities must be disjoint"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _POLICY_MAGIC
            + bytes(self.subject_digest)
            + bytes((NETWORK_CODES[self.network],))
            + bytes((SETUP_SECURITY_MODES[self.setup_security_mode],))
            + bytes(self.chain_genesis_hash)
            + _u(self.maximum_value_sat, 8, "maximum value")
            + _u(self.minimum_committee_members, 2, "minimum committee members")
            + _u(self.minimum_rollback_witnesses, 2, "minimum rollback witnesses")
            + _u(self.minimum_confirmations, 2, "minimum confirmations")
            + _u(len(self.rollback_witness_pubkeys), 2, "rollback witness count")
            + b"".join(bytes(key) for key in self.rollback_witness_pubkeys)
            + _u(len(self.setup_participant_pubkeys), 2, "setup participant count")
            + b"".join(bytes(key) for key in self.setup_participant_pubkeys)
            + _u(len(self.governance_pubkeys), 2, "governance count")
            + _u(self.governance_threshold, 2, "governance threshold")
            + b"".join(bytes(key) for key in self.governance_pubkeys)
            + _u(len(self.role_authorities), 2, "role authority count")
            + b"".join(authority.encoded for authority in self.role_authorities)
        )

    @property
    def digest(self) -> bytes:
        return _h(_POLICY_DOMAIN, self.encoded)

    @property
    def signing_message(self) -> bytes:
        return _h(_POLICY_SIGN_DOMAIN, self.digest)


@dataclass(frozen=True, slots=True)
class SignedFundsSafetyPolicy:
    unsigned: UnsignedFundsSafetyPolicy
    governance_signatures: tuple[tuple[bytes, bytes], ...]
    schema: str = "ranklock-signed-funds-safety-policy-v1"

    def __post_init__(self) -> None:
        keys = tuple(key for key, _signature in self.governance_signatures)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise DeploymentPolicyError("governance signatures are not canonical and unique")
        if any(len(bytes(key)) != _HASH or len(bytes(signature)) != _SIG for key, signature in self.governance_signatures):
            raise DeploymentPolicyError("governance signature entry is malformed")

    def verify(self) -> bool:
        authorized = set(self.unsigned.governance_pubkeys)
        valid = {
            key
            for key, signature in self.governance_signatures
            if key in authorized and verify(self.unsigned.signing_message, key, signature)
        }
        return len(valid) >= self.unsigned.governance_threshold

    @classmethod
    def create(
        cls,
        unsigned: UnsignedFundsSafetyPolicy,
        *,
        governance_secrets: Sequence[int],
    ) -> "SignedFundsSafetyPolicy":
        rows = []
        for secret in governance_secrets:
            key = public_key(int(secret))
            if key not in unsigned.governance_pubkeys:
                raise DeploymentPolicyError("governance secret is not authorized")
            rows.append((key, sign(unsigned.signing_message, int(secret))))
        result = cls(unsigned, tuple(sorted(rows)))
        if not result.verify():
            raise DeploymentPolicyError("governance signature threshold was not met")
        return result


@dataclass(frozen=True, slots=True)
class SecurityAttestation:
    role: str
    subject_digest: bytes
    evidence_digest: bytes
    issued_at: int
    expires_at: int
    signer_pubkey: bytes
    signature: bytes
    schema: str = "ranklock-security-attestation-v1"

    def __post_init__(self) -> None:
        _role(self.role)
        _digest(self.subject_digest, "attestation subject digest")
        if _digest(self.evidence_digest, "attestation evidence digest") == _ZERO:
            raise DeploymentPolicyError("attestation evidence digest must be nonzero")
        _digest(self.signer_pubkey, "attestation signer key")
        if len(bytes(self.signature)) != _SIG:
            raise DeploymentPolicyError("attestation signature must be 64 bytes")
        if not 0 <= int(self.issued_at) < int(self.expires_at) < 2**64:
            raise DeploymentPolicyError("attestation validity window is invalid")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _ATTEST_MAGIC
            + _lp(self.role.encode("ascii"), width=1)
            + bytes(self.subject_digest)
            + bytes(self.evidence_digest)
            + _u(self.issued_at, 8, "issued at")
            + _u(self.expires_at, 8, "expires at")
            + bytes(self.signer_pubkey)
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_ATTEST_SIGN_DOMAIN, self.unsigned_bytes)

    @property
    def digest(self) -> bytes:
        return _h(_ATTEST_DOMAIN, self.unsigned_bytes, self.signature)

    def verify(self) -> bool:
        return verify(self.signing_message, self.signer_pubkey, self.signature)

    @classmethod
    def create(
        cls,
        *,
        role: str,
        subject_digest: bytes,
        evidence_digest: bytes,
        issued_at: int,
        expires_at: int,
        signer_secret: int,
    ) -> "SecurityAttestation":
        placeholder = cls(
            _role(role),
            bytes(subject_digest),
            bytes(evidence_digest),
            int(issued_at),
            int(expires_at),
            public_key(int(signer_secret)),
            bytes(_SIG),
        )
        return cls(
            placeholder.role,
            placeholder.subject_digest,
            placeholder.evidence_digest,
            placeholder.issued_at,
            placeholder.expires_at,
            placeholder.signer_pubkey,
            sign(placeholder.signing_message, int(signer_secret)),
        )


@dataclass(frozen=True, slots=True)
class RuntimeSecurityFacts:
    network: str
    chain_genesis_hash: bytes
    value_at_risk_sat: int
    committee_members: int
    committee_quorum: int
    rollback_witnesses: int
    minimum_confirmations: int
    rollback_witness_pubkeys: tuple[bytes, ...]
    bitcoin_core_consensus_crosscheck: bool
    witness_selected_point_binding: bool
    durable_burn_before_release: bool
    rollback_protection_live: bool
    deterministic_fixture_secrets_absent: bool
    secret_file_permissions_locked: bool
    setup_security_mode: str = "active-mpc"
    independent_scalar_artifacts: bool = False
    all_ack_preimages_required: bool = False
    split_scalar_bundle_verified: bool = False
    schema: str = "ranklock-runtime-security-facts-v4"

    def __post_init__(self) -> None:
        if self.network not in NETWORK_CODES:
            raise DeploymentPolicyError("runtime network is unknown")
        if self.setup_security_mode not in SETUP_SECURITY_MODES:
            raise DeploymentPolicyError("runtime setup security mode is unknown")
        _digest(self.chain_genesis_hash, "runtime chain genesis hash")
        if not 0 <= int(self.value_at_risk_sat) < 2**64:
            raise DeploymentPolicyError("runtime value at risk does not fit u64")
        if not 0 <= int(self.committee_quorum) <= int(self.committee_members) < 2**16:
            raise DeploymentPolicyError("runtime committee dimensions are invalid")
        if not 0 <= int(self.rollback_witnesses) < 2**16:
            raise DeploymentPolicyError("runtime rollback-witness count is invalid")
        if not 1 <= int(self.minimum_confirmations) < 2**16:
            raise DeploymentPolicyError("runtime minimum confirmation depth is invalid")
        keys = self.rollback_witness_pubkeys
        if tuple(sorted(keys)) != keys or len(set(keys)) != len(keys):
            raise DeploymentPolicyError(
                "runtime rollback witness keys are not canonical and unique"
            )
        if any(len(bytes(key)) != _HASH for key in keys):
            raise DeploymentPolicyError("runtime rollback witness key must be 32 bytes")
        if int(self.rollback_witnesses) != len(keys):
            raise DeploymentPolicyError(
                "runtime rollback-witness count differs from the configured identity set"
            )


@dataclass(frozen=True, slots=True)
class DeploymentDecision:
    mode: str
    can_start: bool
    may_authorize_funds: bool
    failures: tuple[str, ...]
    accepted_attestation_digests: tuple[bytes, ...]
    schema: str = "ranklock-deployment-decision-v1"


def evaluate_deployment(
    *,
    mode: str,
    subject: SafetySubject,
    policy: SignedFundsSafetyPolicy | None,
    attestations: Iterable[SecurityAttestation],
    runtime: RuntimeSecurityFacts,
    now: int,
) -> DeploymentDecision:
    mode = str(mode)
    if mode not in DEPLOYMENT_MODES:
        raise DeploymentPolicyError("unknown deployment mode")
    failures: list[str] = []
    accepted: list[bytes] = []

    # Observe mode is intentionally available without authority, but never
    # obtains signing material or permission to affect Bitcoin state.
    if mode == "observe":
        return DeploymentDecision(mode, True, False, tuple(), tuple())

    if policy is None:
        failures.append("governance-signed funds-safety policy is absent")
        return DeploymentDecision(mode, mode == "canary", False, tuple(failures), tuple())
    if not policy.verify():
        failures.append("funds-safety policy governance threshold failed")
    unsigned = policy.unsigned
    if unsigned.subject_digest != subject.digest:
        failures.append("software/artifact subject differs from signed policy")
    if runtime.network != unsigned.network:
        failures.append("runtime Bitcoin network differs from signed policy")
    if runtime.setup_security_mode != unsigned.setup_security_mode:
        failures.append("runtime setup security mode differs from signed policy")
    if runtime.chain_genesis_hash != unsigned.chain_genesis_hash:
        failures.append("runtime chain genesis differs from signed policy")
    if runtime.value_at_risk_sat > unsigned.maximum_value_sat:
        failures.append("value at risk exceeds signed policy cap")
    if runtime.committee_members < unsigned.minimum_committee_members:
        failures.append("committee is below signed minimum")
    if runtime.committee_quorum != runtime.committee_members:
        failures.append("committee release is not N-of-N")
    if runtime.rollback_witnesses < unsigned.minimum_rollback_witnesses:
        failures.append("rollback-witness set is below signed minimum")
    if runtime.minimum_confirmations < unsigned.minimum_confirmations:
        failures.append("runtime confirmation depth is below signed minimum")
    if runtime.rollback_witness_pubkeys != unsigned.rollback_witness_pubkeys:
        failures.append("runtime rollback-witness identities differ from signed policy")

    boolean_facts = {
        "Bitcoin Core consensus cross-check is not live": runtime.bitcoin_core_consensus_crosscheck,
        "witness-to-point binding is not enforced": runtime.witness_selected_point_binding,
        "durable burn-before-release is not enforced": runtime.durable_burn_before_release,
        "remote rollback protection is not live": runtime.rollback_protection_live,
        "deterministic fixture secrets are present": runtime.deterministic_fixture_secrets_absent,
        "secret-file permissions are not locked": runtime.secret_file_permissions_locked,
    }
    if unsigned.setup_security_mode == "split-scalar-n-of-n":
        split_scalar_facts = {
            "split-scalar retained objects are not independently generated": runtime.independent_scalar_artifacts,
            "Bitcoin ACK does not require every scalar-share preimage": runtime.all_ack_preimages_required,
            "split-scalar bundle signatures/scale proofs are not verified": runtime.split_scalar_bundle_verified,
        }
        boolean_facts.update(split_scalar_facts)
    failures.extend(message for message, passed in boolean_facts.items() if not passed)

    required_roles = production_roles_for_mode(unsigned.setup_security_mode)
    authorities: Mapping[str, RoleAuthority] = {
        authority.role: authority for authority in unsigned.role_authorities
    }
    valid_by_role: dict[str, set[bytes]] = {role: set() for role in required_roles}
    signed_by_identity: dict[tuple[str, bytes], dict[bytes, SecurityAttestation]] = {}
    for attestation in attestations:
        authority = authorities.get(attestation.role)
        if (
            authority is None
            or attestation.signer_pubkey not in authority.authorized_pubkeys
            or not attestation.verify()
        ):
            continue
        identity = (attestation.role, attestation.signer_pubkey)
        signed_by_identity.setdefault(identity, {})[attestation.digest] = attestation

    for (role, signer), signed_rows in sorted(signed_by_identity.items()):
        if len(signed_rows) != 1:
            failures.append(
                f"authorized attestation signer equivocated for role: {role}"
            )
            continue
        attestation = next(iter(signed_rows.values()))
        if (
            attestation.subject_digest == subject.digest
            and attestation.issued_at <= int(now) < attestation.expires_at
        ):
            valid_by_role[role].add(signer)
            accepted.append(attestation.digest)
    for role in required_roles:
        authority = authorities[role]
        if len(valid_by_role[role]) < authority.minimum_signatures:
            failures.append(
                f"security attestation threshold not met for role: {role}"
            )

    may_authorize = not failures
    # Canary mode may start only when it is guaranteed not to authorize funds.
    can_start = may_authorize if mode == "enforce" else True
    return DeploymentDecision(
        mode=mode,
        can_start=can_start,
        may_authorize_funds=may_authorize and mode == "enforce",
        failures=tuple(failures),
        accepted_attestation_digests=tuple(sorted(set(accepted))),
    )
