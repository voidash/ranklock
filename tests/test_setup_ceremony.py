from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.bip340 import public_key
from ranklock.setup_ceremony import (
    SetupCeremonyConfig,
    SetupCeremonyError,
    SetupEntropyTranscript,
    SignedEntropyCommitment,
    SignedEntropyReveal,
)


def _fixture():
    secrets = (11, 13, 17)
    keys = tuple(sorted(public_key(secret) for secret in secrets))
    by_key = {public_key(secret): secret for secret in secrets}
    ordered_secrets = tuple(by_key[key] for key in keys)
    config = SetupCeremonyConfig(
        context_digest=sha256(b"context").digest(),
        generator_code_hash=sha256(b"generator").digest(),
        ceremony_epoch=7,
        participant_pubkeys=keys,
    )
    entropies = tuple(sha256(b"entropy" + bytes((i,))).digest() for i in range(3))
    nonces = tuple(sha256(b"nonce" + bytes((i,))).digest() for i in range(3))
    commitments = tuple(
        SignedEntropyCommitment.create(
            config,
            participant_index=i,
            participant_secret=secret,
            entropy=entropies[i],
            nonce=nonces[i],
        )
        for i, secret in enumerate(ordered_secrets)
    )
    reveals = tuple(
        SignedEntropyReveal.create(
            config,
            commitments[i],
            participant_secret=secret,
            entropy=entropies[i],
            nonce=nonces[i],
        )
        for i, secret in enumerate(ordered_secrets)
    )
    return config, ordered_secrets, commitments, reveals


def test_commit_reveal_roundtrip_and_deterministic_seed():
    config, _secrets, commitments, reveals = _fixture()
    assert SetupCeremonyConfig.parse(config.encoded) == config
    assert all(SignedEntropyCommitment.parse(item.encoded) == item for item in commitments)
    assert all(SignedEntropyReveal.parse(item.encoded) == item for item in reveals)
    transcript = SetupEntropyTranscript.assemble(config, commitments, reveals)
    assert transcript.combined_seed == SetupEntropyTranscript(
        config, commitments, reveals
    ).combined_seed
    assert len(transcript.transcript_digest) == 32


def test_missing_duplicate_or_wrong_opening_is_rejected():
    config, secrets, commitments, reveals = _fixture()
    with pytest.raises(SetupCeremonyError, match="incomplete"):
        SetupEntropyTranscript.assemble(config, commitments[:-1], reveals[:-1])
    with pytest.raises(SetupCeremonyError, match="duplicate"):
        SetupEntropyTranscript.assemble(
            config,
            commitments[:-1] + (commitments[0],),
            reveals,
        )

    wrong = replace(reveals[0], entropy=bytes(32))
    assert not wrong.verify(config, commitments[0])
    with pytest.raises(SetupCeremonyError):
        SetupEntropyTranscript.assemble(config, commitments, (wrong,) + reveals[1:])

    with pytest.raises(SetupCeremonyError):
        SignedEntropyReveal.create(
            config,
            commitments[0],
            participant_secret=secrets[0],
            entropy=bytes(32),
            nonce=reveals[0].nonce,
        )


def test_commitment_signature_and_ceremony_identity_bind():
    config, _secrets, commitments, reveals = _fixture()
    bad_signature = replace(commitments[0], signature=bytes(64))
    assert not bad_signature.verify(config)

    another = replace(config, ceremony_epoch=config.ceremony_epoch + 1)
    assert commitments[0].ceremony_id != another.ceremony_id
    assert not reveals[0].verify(another, commitments[0])
