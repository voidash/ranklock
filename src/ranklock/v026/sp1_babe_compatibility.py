"""Exact fail-closed compatibility audit for SP1 Groth16 and BABE.

The imported Strata counterproof uses SP1 6.2.4's universal BN254 Groth16
verifying key.  BABE Construction 1, in contrast, is proved for the
deterministic non-zero-knowledge Groth16 relation ``R'``.  This module parses
the exact gnark verifying-key wire format, verifies the imported artifact
manifest, and records the two concrete incompatibilities rather than treating
unrelated caller-provided hashes as qualification evidence.

This is an incompatibility certificate, not a production proof-system bridge.
It cannot make a graph fundable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from ..babe_positive_lock import BabePositiveLockError, PositiveGroth16VerifyingKey
from ..bn254_real import CURVE_ORDER, decompress_g1, decompress_g2

_ASSESSMENT_SCHEMA = "ranklock-v026-sp1-babe-compatibility-assessment-v1"
_ARTIFACT_SCHEMA = "ranklock-v026-imported-counterproof-artifacts-v1"
_STATEMENT_SCHEMA = "ranklock-v026-sp1-groth16-statement-v1"
_VK_SCHEMA = "ranklock-sp1-gnark-groth16-vk-v1"
_BINDING_DOMAIN = b"ranklock/v026/imported-counterproof-artifacts/v1\x00"

SP1_VERSION = "6.2.4"
SP1_GROTH16_VK_SHA256 = (
    "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
)
SP1_GNARK_COMMIT = "cd7874155e26"
SP1_GNARK_PROVE_SOURCE_SHA256 = (
    "a3ea3a8fcf15f5b5f1a4b6ab610f258d78ffbba9b51d174ce70e9d03a5dc80ad"
)
SP1_GNARK_PROVE_SOURCE_URL = (
    "https://raw.githubusercontent.com/p4u/gnark/"
    "cd7874155e26/backend/groth16/bn254/prove.go"
)
STRATA_COUNTERPROOF_TYPES_SOURCE_SHA256 = (
    "9068a5a2f8ae302c8f4d4a09dcd4ad88447068f2eca321f0a240dfcf7cdf3d84"
)
STRATA_COUNTERPROOF_TYPES_SOURCE_URL = (
    "https://raw.githubusercontent.com/alpenlabs/strata-bridge/"
    "3362fa450c48bd7df4009d827f01107945658e40/"
    "crates/proofs/bridge-counterproof/src/types.rs"
)
BABE_PAPER_URL = "https://docs.babylonlabs.io/papers/BABE_Research_Paper_Jan_2026.pdf"
BABE_PAPER_SHA256 = "bec556af85bf0b42c9c90d9ad6bf78d74ebb7028f3c679c6b582d7b70b14445a"

_IMPORTED_MANIFEST_SHA256 = (
    "989ebdaea348ddfbe9042c9dabbb31fd261e82d0bfcac29791093f47af43e723"
)
_IMPORTED_COUNTERPROOF_ELF_SHA256 = (
    "9ae1d4ef5816b598cf9b02be659d3bae6535151834f1fd77a5f4b572a60be8b7"
)
_IMPORTED_COUNTERPROOF_PREDICATE_SHA256 = (
    "50d8da4a706e4c07f3e4d8323557554ef6c476eaa340af468d5237f7a63437bd"
)
_IMPORTED_COUNTERPROOF_VKEY_SHA256 = (
    "075662f3f59d9a239b92873e130e3a51a7de928566245d504b3e92d09a2b3e0b"
)
_IMPORTED_COUNTERPROOF_PROGRAM_VKEY = bytes.fromhex(
    "00fc65c2f437f49e8cb93e196c917724ca679eaee622295320ecc25b07e4d189"
)
_IMPORTED_BINDING_DIGEST = bytes.fromhex(
    "0390e7017f569709f559ea2023217e13b33b782e2fe72d8b9520d174fe10a7e9"
)
_IMPORTED_STRATA_BRIDGE_REF = "refs/tags/v0.3.0-rc.4"
_IMPORTED_STRATA_BRIDGE_SHA = "3362fa450c48bd7df4009d827f01107945658e40"
_IMPORTED_FILE_NAMES = (
    "asm-params.json",
    "asm-vk.json",
    "bridge-proof-vkey.bin",
    "bridge-proof-vkey.bin.sha256",
    "bridge-proof.elf",
    "bridge-proof.elf.sha256",
    "bridge-proof.predicate",
    "counterproof-vkey.bin",
    "counterproof-vkey.bin.sha256",
    "counterproof.elf",
    "counterproof.elf.sha256",
    "counterproof.predicate",
    "manifest.json",
    "moho-vk.json",
)

# Exact public constant shipped by sp1-verifier 6.2.4.  Keeping the bytes here
# makes the parser and compatibility result reproducible without treating a
# machine-local Cargo cache as evidence.
SP1_GROTH16_VK_BYTES = bytes.fromhex(
    "e1c7d728a5fd961fc179ec5eab938f564deba5b271e1c90c2c29a79648418fc1"
    "82e78e216b27cb2b30abd22d17fb65b747ad8050d18e543498522d01a2c3fe79"
    "dc3c9339849225980c7d3f824f80d19e2a9c2554b6ab2160fa9635528f693fc0"
    "0d964538da2653f2e62499571e6c78afb8909d3ea8107f306bd6928253680a3a"
    "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "d7e00b2ca4f62668135017ed8a68894e104ac26dfd9bf376634b42af9e5ae50e"
    "91b7e9276171bb0efd647fc63e38bbfba3076f20daca8cd52bcc7284d9b1c6eb"
    "1723616533dd6ae53502c9c506a81f23f543d68750b5133ebfbe1f4746b3b011"
    "00000006acd6bf7f164af0b6b0bbbe0fdcb06ee0c1ba07f8e6eb2f9f3943a90c"
    "b1d402908f5460f3b7221705435e745da21e276536379c0113c13c4255e7ae10"
    "1f1e90bf8b0ae6e491bc04c544da9e8cd4857d201b4cfa0222dbe96aac97f044"
    "fdf1c922c97c875a6ebd0999b06e7267ff3d8a6bf859bb9635abae07cb6b3534"
    "ba409a839807204ddcd27506ba72e17b55227b0bf310136ecb40c74acd52f3cc"
    "fbcba9f7808c7b7c98d78c07a2c4be5f6be7082ba41021611f9a2dfc016f8bbb"
    "37d36bee0000000000000000"
)


class Sp1BabeCompatibilityError(ValueError):
    """The SP1/BABE compatibility input or imported artifact is invalid."""


def _sha256(value: bytes) -> bytes:
    return sha256(bytes(value)).digest()


def _fixed(value: bytes, size: int, name: str) -> bytes:
    value = bytes(value)
    if len(value) != size:
        raise Sp1BabeCompatibilityError(f"{name} must be exactly {size} bytes")
    return value


def _field_bytes(value: bytes, name: str) -> bytes:
    value = _fixed(value, 32, name)
    if int.from_bytes(value, "big") >= CURVE_ORDER:
        raise Sp1BabeCompatibilityError(f"{name} is not a canonical BN254 scalar")
    return value


def _manifest_object(value: object, name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise Sp1BabeCompatibilityError(f"manifest {name} must be an object")
    return value


def _manifest_string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise Sp1BabeCompatibilityError(f"manifest {name} must be a nonempty string")
    return value


@dataclass(frozen=True, slots=True)
class Sp1GnarkVerifyingKeyV1:
    """Strict parse of SP1's gnark Groth16 verifying-key bytes."""

    raw_bytes: bytes
    positive_vk: PositiveGroth16VerifyingKey
    public_input_count: int
    commitment_index_arrays: tuple[tuple[int, ...], ...]
    commitment_key_count: int
    schema: str = _VK_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _VK_SCHEMA:
            raise Sp1BabeCompatibilityError("unknown SP1 Groth16 VK schema")
        if len(self.raw_bytes) != 492 or self.digest.hex() != SP1_GROTH16_VK_SHA256:
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK is not the pinned 6.2.4 universal key"
            )
        if self.public_input_count != 5:
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK must expose exactly five public inputs"
            )
        if len(self.positive_vk.ic_g1) != self.public_input_count + 1:
            raise Sp1BabeCompatibilityError("SP1 Groth16 VK IC count is inconsistent")
        if (
            self.positive_vk.alpha_g1 != self.raw_bytes[0:32]
            or self.positive_vk.beta_g2 != self.raw_bytes[64:128]
            or self.positive_vk.gamma_g2 != self.raw_bytes[128:192]
            or self.positive_vk.delta_g2 != self.raw_bytes[224:288]
            or self.positive_vk.ic_g1
            != tuple(
                self.raw_bytes[292 + 32 * index : 324 + 32 * index]
                for index in range(6)
            )
            or self.positive_vk.context != b"sp1-groth16-v6.2.4-universal-vk"
            or self.positive_vk.schema != "ranklock-positive-groth16-vk-v1"
        ):
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK projection disagrees with its wire bytes"
            )
        if self.commitment_index_arrays or self.commitment_key_count != 0:
            raise Sp1BabeCompatibilityError(
                "this SP1 universal VK must not use Groth16 commitments"
            )

    @property
    def digest(self) -> bytes:
        return _sha256(self.raw_bytes)

    @classmethod
    def parse(cls, raw: bytes) -> Sp1GnarkVerifyingKeyV1:
        """Parse the exact gnark format and reject truncation or trailing bytes."""

        raw = bytes(raw)
        if len(raw) < 296:
            raise Sp1BabeCompatibilityError("truncated SP1 Groth16 VK")
        try:
            alpha_g1 = raw[0:32]
            beta_g1 = raw[32:64]
            beta_g2 = raw[64:128]
            gamma_g2 = raw[128:192]
            delta_g1 = raw[192:224]
            delta_g2 = raw[224:288]
            decompress_g1(alpha_g1)
            decompress_g1(beta_g1)
            decompress_g2(beta_g2)
            decompress_g2(gamma_g2)
            decompress_g1(delta_g1)
            decompress_g2(delta_g2)
        except (ValueError, ZeroDivisionError, OverflowError) as exc:
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK contains an invalid group point"
            ) from exc

        ic_count = int.from_bytes(raw[288:292], "big")
        if not 2 <= ic_count <= 4096:
            raise Sp1BabeCompatibilityError("SP1 Groth16 VK IC count is invalid")
        offset = 292
        ic_end = offset + 32 * ic_count
        if ic_end + 4 > len(raw):
            raise Sp1BabeCompatibilityError("truncated SP1 Groth16 VK IC roster")
        ic_g1 = tuple(
            raw[offset + 32 * i : offset + 32 * (i + 1)] for i in range(ic_count)
        )
        try:
            for point in ic_g1:
                decompress_g1(point)
        except (ValueError, ZeroDivisionError, OverflowError) as exc:
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK contains an invalid IC point"
            ) from exc
        offset = ic_end

        array_count = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        if array_count != 0:
            raise Sp1BabeCompatibilityError(
                "this SP1 universal VK unexpectedly uses commitment arrays"
            )
        if offset + 4 > len(raw):
            raise Sp1BabeCompatibilityError(
                "truncated SP1 Groth16 VK commitment-key count"
            )
        commitment_key_count = int.from_bytes(raw[offset : offset + 4], "big")
        offset += 4
        if commitment_key_count != 0:
            raise Sp1BabeCompatibilityError(
                "this SP1 universal VK unexpectedly uses commitment keys"
            )
        if offset != len(raw):
            raise Sp1BabeCompatibilityError("trailing SP1 Groth16 VK bytes")

        try:
            positive_vk = PositiveGroth16VerifyingKey(
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                ic_g1,
                b"sp1-groth16-v6.2.4-universal-vk",
            )
        except (
            BabePositiveLockError,
            ValueError,
            ZeroDivisionError,
            OverflowError,
        ) as exc:
            raise Sp1BabeCompatibilityError(
                "SP1 Groth16 VK cannot be projected into the BABE verifier profile"
            ) from exc
        return cls(raw, positive_vk, ic_count - 1, (), commitment_key_count)


@dataclass(frozen=True, slots=True)
class Sp1Groth16StatementV1:
    """The exact five scalar inputs verified by SP1 6.2.4 Groth16."""

    program_vkey_hash: bytes
    committed_values_digest: bytes
    exit_code: bytes
    vk_root: bytes
    proof_nonce: bytes
    schema: str = _STATEMENT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _STATEMENT_SCHEMA:
            raise Sp1BabeCompatibilityError("unknown SP1 Groth16 statement schema")
        for value, name in (
            (self.program_vkey_hash, "program vkey hash"),
            (self.committed_values_digest, "committed-values digest"),
            (self.exit_code, "exit code"),
            (self.vk_root, "VK root"),
            (self.proof_nonce, "proof nonce"),
        ):
            _field_bytes(value, name)

    @property
    def public_inputs(self) -> tuple[int, ...]:
        return tuple(
            int.from_bytes(value, "big")
            for value in (
                self.program_vkey_hash,
                self.committed_values_digest,
                self.exit_code,
                self.vk_root,
                self.proof_nonce,
            )
        )

    @classmethod
    def for_counterproof_output(
        cls,
        *,
        program_vkey_hash: bytes,
        operator_xonly_pubkey: bytes,
        game_index: int,
        vk_root: bytes,
        proof_nonce: bytes,
    ) -> Sp1Groth16StatementV1:
        """Derive SP1's SHA-256 public-values input from exact SSZ output bytes."""

        operator_xonly_pubkey = _fixed(
            operator_xonly_pubkey, 32, "operator x-only public key"
        )
        if type(game_index) is not int or not 0 <= game_index <= 0xFFFF_FFFF:
            raise Sp1BabeCompatibilityError("game index must be a u32")
        public_values = operator_xonly_pubkey + game_index.to_bytes(4, "little")
        committed_values_digest = bytearray(_sha256(public_values))
        committed_values_digest[0] &= 0x1F
        return cls(
            _field_bytes(program_vkey_hash, "program vkey hash"),
            bytes(committed_values_digest),
            bytes(32),
            _field_bytes(vk_root, "VK root"),
            _field_bytes(proof_nonce, "proof nonce"),
        )


@dataclass(frozen=True, slots=True)
class ImportedCounterproofArtifactEvidenceV1:
    """Byte-exact evidence for the imported production counterproof bundle."""

    manifest_sha256: bytes
    counterproof_elf_sha256: bytes
    counterproof_predicate_sha256: bytes
    counterproof_program_vkey: bytes
    predicate_universal_vk_hash_prefix: bytes
    binding_digest: bytes
    manifest_schema: int
    environment: str
    strata_bridge_ref: str
    strata_bridge_sha: str
    imported_file_names: tuple[str, ...]
    schema: str = _ARTIFACT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != _ARTIFACT_SCHEMA:
            raise Sp1BabeCompatibilityError("unknown imported-artifact schema")
        for value, name in (
            (self.manifest_sha256, "manifest digest"),
            (self.counterproof_elf_sha256, "counterproof ELF digest"),
            (self.counterproof_predicate_sha256, "counterproof predicate digest"),
            (self.counterproof_program_vkey, "counterproof program vkey"),
            (self.binding_digest, "artifact binding digest"),
        ):
            _fixed(value, 32, name)
        _fixed(
            self.predicate_universal_vk_hash_prefix,
            4,
            "predicate universal-VK hash prefix",
        )
        if self.imported_file_names != _IMPORTED_FILE_NAMES:
            raise Sp1BabeCompatibilityError(
                "imported counterproof artifact roster is not exact"
            )
        if self.binding_digest != _IMPORTED_BINDING_DIGEST:
            raise Sp1BabeCompatibilityError(
                "imported counterproof artifact binding digest is not exact"
            )
        exact_values = (
            (self.manifest_sha256.hex(), _IMPORTED_MANIFEST_SHA256, "manifest"),
            (
                self.counterproof_elf_sha256.hex(),
                _IMPORTED_COUNTERPROOF_ELF_SHA256,
                "counterproof ELF",
            ),
            (
                self.counterproof_predicate_sha256.hex(),
                _IMPORTED_COUNTERPROOF_PREDICATE_SHA256,
                "counterproof predicate",
            ),
            (
                self.counterproof_program_vkey.hex(),
                _IMPORTED_COUNTERPROOF_PROGRAM_VKEY.hex(),
                "counterproof program vkey",
            ),
        )
        for actual, expected, name in exact_values:
            if actual != expected:
                raise Sp1BabeCompatibilityError(
                    f"imported {name} is not the pinned production artifact"
                )
        if self.predicate_universal_vk_hash_prefix != bytes.fromhex(
            SP1_GROTH16_VK_SHA256[:8]
        ):
            raise Sp1BabeCompatibilityError(
                "counterproof predicate uses another universal Groth16 VK"
            )
        if (
            self.manifest_schema != 3
            or self.environment != "prod"
            or self.strata_bridge_ref != _IMPORTED_STRATA_BRIDGE_REF
            or self.strata_bridge_sha != _IMPORTED_STRATA_BRIDGE_SHA
        ):
            raise Sp1BabeCompatibilityError(
                "imported counterproof identity is not the pinned production bundle"
            )


def inspect_imported_counterproof_artifacts(
    artifact_dir: Path,
) -> ImportedCounterproofArtifactEvidenceV1:
    """Validate the exact imported manifest, ELF, predicate, and program vkey."""

    try:
        directory = Path(artifact_dir).resolve(strict=True)
        entries = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
        imported_file_names = tuple(path.name for path in entries)
    except OSError as exc:
        raise Sp1BabeCompatibilityError(
            "failed to inspect imported counterproof artifact directory"
        ) from exc
    if imported_file_names != _IMPORTED_FILE_NAMES or not all(
        path.is_file() for path in entries
    ):
        raise Sp1BabeCompatibilityError(
            "imported counterproof artifact roster is not exact"
        )
    paths = {
        "manifest": directory / "manifest.json",
        "elf": directory / "counterproof.elf",
        "predicate": directory / "counterproof.predicate",
        "vkey": directory / "counterproof-vkey.bin",
    }
    try:
        values = {name: path.read_bytes() for name, path in paths.items()}
    except OSError as exc:
        raise Sp1BabeCompatibilityError(
            "failed to read imported counterproof artifacts"
        ) from exc
    exact_hashes = {
        "manifest": _IMPORTED_MANIFEST_SHA256,
        "elf": _IMPORTED_COUNTERPROOF_ELF_SHA256,
        "predicate": _IMPORTED_COUNTERPROOF_PREDICATE_SHA256,
        "vkey": _IMPORTED_COUNTERPROOF_VKEY_SHA256,
    }
    for name, expected_digest in exact_hashes.items():
        if _sha256(values[name]).hex() != expected_digest:
            raise Sp1BabeCompatibilityError(
                f"imported counterproof {name} is not the pinned production artifact"
            )
    try:
        manifest = json.loads(values["manifest"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Sp1BabeCompatibilityError(
            "counterproof manifest is invalid JSON"
        ) from exc
    manifest = _manifest_object(manifest, "root")
    if type(manifest.get("schema")) is not int or manifest["schema"] != 3:
        raise Sp1BabeCompatibilityError("counterproof manifest schema is not 3")
    environment = _manifest_string(manifest.get("env"), "environment")
    if environment != "prod":
        raise Sp1BabeCompatibilityError("counterproof manifest is not production")
    sha_manifest = _manifest_object(manifest.get("sha256"), "sha256")
    expected_hashes = {
        "counterproof.elf": _sha256(values["elf"]).hex(),
        "counterproof.predicate": _sha256(values["predicate"]).hex(),
        "counterproof-vkey.bin": _sha256(values["vkey"]).hex(),
    }
    for name, digest in expected_hashes.items():
        if sha_manifest.get(name) != digest:
            raise Sp1BabeCompatibilityError(
                f"counterproof manifest hash mismatch for {name}"
            )
    vkeys = _manifest_object(manifest.get("vkeys"), "vkeys")
    if vkeys.get("counterproof") != values["vkey"].hex():
        raise Sp1BabeCompatibilityError(
            "counterproof program vkey disagrees with the manifest"
        )
    if values["vkey"] != _IMPORTED_COUNTERPROOF_PROGRAM_VKEY:
        raise Sp1BabeCompatibilityError(
            "counterproof program vkey is not the pinned production vkey"
        )
    predicates = _manifest_object(manifest.get("predicates"), "predicates")
    try:
        predicate_text = values["predicate"].decode("ascii")
    except UnicodeDecodeError as exc:
        raise Sp1BabeCompatibilityError("counterproof predicate is not ASCII") from exc
    if predicates.get("counterproof") != predicate_text:
        raise Sp1BabeCompatibilityError(
            "counterproof predicate disagrees with the manifest"
        )
    prefix = "Sp1Groth16:"
    if not predicate_text.startswith(prefix):
        raise Sp1BabeCompatibilityError("counterproof predicate has the wrong type")
    try:
        predicate_bytes = bytes.fromhex(predicate_text[len(prefix) :])
    except ValueError as exc:
        raise Sp1BabeCompatibilityError(
            "counterproof predicate hex is invalid"
        ) from exc
    if len(predicate_bytes) < 4:
        raise Sp1BabeCompatibilityError("counterproof predicate is truncated")
    expected_prefix = bytes.fromhex(SP1_GROTH16_VK_SHA256[:8])
    if predicate_bytes[:4] != expected_prefix:
        raise Sp1BabeCompatibilityError(
            "counterproof predicate uses another universal Groth16 VK"
        )
    bridge = _manifest_object(manifest.get("strata_bridge"), "strata_bridge")
    bridge_ref = _manifest_string(bridge.get("ref"), "strata-bridge ref")
    bridge_sha = _manifest_string(bridge.get("sha"), "strata-bridge SHA")
    if bridge_ref != _IMPORTED_STRATA_BRIDGE_REF:
        raise Sp1BabeCompatibilityError("unexpected strata-bridge ref")
    if bridge_sha != _IMPORTED_STRATA_BRIDGE_SHA:
        raise Sp1BabeCompatibilityError("unexpected strata-bridge SHA")
    if len(bridge_sha) != 40:
        raise Sp1BabeCompatibilityError("strata-bridge SHA is not 40 hex characters")
    try:
        bytes.fromhex(bridge_sha)
    except ValueError as exc:
        raise Sp1BabeCompatibilityError("strata-bridge SHA is not hexadecimal") from exc

    binding = sha256(_BINDING_DOMAIN)
    for name in ("manifest", "elf", "predicate", "vkey"):
        value = values[name]
        binding.update(len(value).to_bytes(8, "big"))
        binding.update(value)
    return ImportedCounterproofArtifactEvidenceV1(
        _sha256(values["manifest"]),
        _sha256(values["elf"]),
        _sha256(values["predicate"]),
        values["vkey"],
        predicate_bytes[:4],
        binding.digest(),
        manifest["schema"],
        environment,
        bridge_ref,
        bridge_sha,
        imported_file_names,
    )


@dataclass(frozen=True, slots=True)
class Sp1BabeCompatibilityAssessmentV1:
    """Immutable conclusion for direct use of imported SP1 proofs in BABE."""

    artifacts: ImportedCounterproofArtifactEvidenceV1
    universal_vk_sha256: bytes
    production_public_input_count: int
    ranklock_extended_public_input_count: int
    production_vk_accepts_ranklock_extended_layout: bool = field(
        default=False, init=False
    )
    selected_commitment_in_counterproof_public_values: bool = field(
        default=False, init=False
    )
    sp1_gnark_prover_samples_random_r_and_s: bool = field(default=True, init=False)
    babe_deterministic_r_prime_instantiated: bool = field(default=False, init=False)
    complete_r1cs_present_in_import: bool = field(default=False, init=False)
    complete_proving_key_present_in_import: bool = field(default=False, init=False)
    projectivizer_present_in_import: bool = field(default=False, init=False)
    direct_integration_compatible: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    sp1_version: str = field(default=SP1_VERSION, init=False)
    gnark_commit: str = field(default=SP1_GNARK_COMMIT, init=False)
    gnark_prove_source_sha256: str = field(
        default=SP1_GNARK_PROVE_SOURCE_SHA256, init=False
    )
    gnark_prove_source_url: str = field(default=SP1_GNARK_PROVE_SOURCE_URL, init=False)
    counterproof_types_source_sha256: str = field(
        default=STRATA_COUNTERPROOF_TYPES_SOURCE_SHA256, init=False
    )
    counterproof_types_source_url: str = field(
        default=STRATA_COUNTERPROOF_TYPES_SOURCE_URL, init=False
    )
    schema: str = field(default=_ASSESSMENT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.artifacts, ImportedCounterproofArtifactEvidenceV1):
            raise Sp1BabeCompatibilityError(
                "SP1/BABE assessment artifacts have the wrong type"
            )
        if self.production_public_input_count != 5:
            raise Sp1BabeCompatibilityError(
                "production SP1 Groth16 public-input count must remain five"
            )
        if self.ranklock_extended_public_input_count != 7:
            raise Sp1BabeCompatibilityError(
                "RankLock extended public-input count must remain seven"
            )
        if self.universal_vk_sha256.hex() != SP1_GROTH16_VK_SHA256:
            raise Sp1BabeCompatibilityError("unexpected SP1 universal VK digest")


def assess_sp1_babe_compatibility(
    artifact_dir: Path,
) -> Sp1BabeCompatibilityAssessmentV1:
    """Verify current artifacts and return the fail-closed compatibility result."""

    artifacts = inspect_imported_counterproof_artifacts(artifact_dir)
    parsed_vk = Sp1GnarkVerifyingKeyV1.parse(SP1_GROTH16_VK_BYTES)
    if parsed_vk.digest.hex() != SP1_GROTH16_VK_SHA256:
        raise Sp1BabeCompatibilityError("embedded SP1 universal VK digest mismatch")
    return Sp1BabeCompatibilityAssessmentV1(
        artifacts,
        parsed_vk.digest,
        parsed_vk.public_input_count,
        parsed_vk.public_input_count + 2,
    )
