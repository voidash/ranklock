from __future__ import annotations

"""t-of-n Feldman VSS: the properties that make operator churn possible.

The n-of-n XOR sharing these replace had a failure mode that disqualified it
for a bridge: losing one participant makes every retained slot bound to that
committee permanently unopenable, so an operator leaving is fund loss rather
than a membership change. These tests pin the three properties that fix it --
any t reconstruct, fewer than t fail closed, and a committee can be replaced
without invalidating the public commitment.
"""

import secrets

import pytest

from ranklock.threshold_sharing import (
    FeldmanCommitment,
    ThresholdSharingError,
    VssShare,
    reconstruct,
    reshare,
    split_secret,
    verify_share,
)

SEED = secrets.token_bytes(32)
LABEL = secrets.token_bytes(16)


def test_any_threshold_subset_reconstructs_and_smaller_ones_do_not():
    shares, commitment = split_secret(SEED, threshold=3, participants=5)

    # Every 3-subset works, not merely the first one.
    for picks in ((0, 1, 2), (1, 3, 4), (0, 2, 4), (2, 3, 4)):
        subset = [shares[i] for i in picks]
        assert reconstruct(subset, threshold=3, commitment=commitment) == SEED

    with pytest.raises(ThresholdSharingError, match="need 3 shares"):
        reconstruct(shares[:2], threshold=3)


def test_below_threshold_fails_closed_rather_than_returning_a_wrong_secret():
    """Individually valid shares interpolated short must not yield bytes.

    Lagrange over too few points produces a wrong value, not an error. The
    limb range check catches that only probabilistically, so reconstruction is
    additionally compared against the committed constant term.
    """

    shares, commitment = split_secret(SEED, threshold=4, participants=6)
    with pytest.raises(ThresholdSharingError, match="below the threshold"):
        reconstruct(shares[:3], threshold=3, commitment=commitment)


def test_every_share_verifies_and_a_tampered_one_is_attributable():
    """The property XOR sharing could not offer: name the faulty participant."""

    shares, commitment = split_secret(SEED, threshold=3, participants=5)
    assert all(verify_share(share, commitment) for share in shares)

    tampered = VssShare(
        index=shares[0].index,
        limbs=(shares[0].limbs[0] ^ 1,) + shares[0].limbs[1:],
    )
    assert not verify_share(tampered, commitment)

    with pytest.raises(ThresholdSharingError, match="participant index 1"):
        reconstruct([tampered, shares[1], shares[2]], threshold=3, commitment=commitment)


def test_a_committee_can_be_replaced_without_changing_the_public_commitment():
    """Operator churn. This is the whole point of the module.

    The commitment digest hashes only the constant terms, so resharing to a
    different committee -- different size, different threshold -- leaves it
    fixed. Any artifact already bound to it stays valid across the change.
    """

    shares, commitment = split_secret(SEED, threshold=3, participants=5)
    original_digest = commitment.digest

    rotated, new_commitment = reshare(
        shares[:3],
        threshold=3,
        new_threshold=4,
        new_participants=7,
        commitment=commitment,
    )

    assert new_commitment.digest == original_digest, "artifacts must survive churn"
    assert len(rotated) == 7
    assert new_commitment.threshold == 4
    assert all(verify_share(share, new_commitment) for share in rotated)
    assert reconstruct(rotated[:4], threshold=4, commitment=new_commitment) == SEED


def test_a_retired_share_no_longer_verifies_against_the_new_committee():
    """Resharing randomises the higher coefficients, so old shares are stale.

    Note what this does NOT provide: the old *set* still reconstructs the
    secret among themselves. Retiring a participant is an operational step --
    they must delete their material -- and no cryptography here can force it.
    """

    shares, commitment = split_secret(SEED, threshold=3, participants=5)
    rotated, new_commitment = reshare(
        shares[:3],
        threshold=3,
        new_threshold=3,
        new_participants=5,
        commitment=commitment,
    )

    assert not verify_share(shares[0], new_commitment)
    # And the honest warning: the old quorum still works on the old commitment.
    assert reconstruct(shares[:3], threshold=3, commitment=commitment) == SEED
    assert rotated[0].limbs != shares[0].limbs


def test_labels_and_seeds_both_share_cleanly():
    """16-byte labels are one limb, 32-byte seeds are two."""

    label_shares, label_commitment = split_secret(LABEL, threshold=2, participants=3)
    assert label_commitment.limb_count == 1
    assert reconstruct(label_shares[:2], threshold=2, commitment=label_commitment) == LABEL

    seed_shares, seed_commitment = split_secret(SEED, threshold=2, participants=3)
    assert seed_commitment.limb_count == 2
    assert reconstruct(seed_shares[:2], threshold=2, commitment=seed_commitment) == SEED


def test_degenerate_and_malformed_parameters_are_refused():
    with pytest.raises(ThresholdSharingError, match="at least the threshold"):
        split_secret(SEED, threshold=4, participants=3)
    with pytest.raises(ThresholdSharingError, match="at least 1"):
        split_secret(SEED, threshold=0, participants=3)
    with pytest.raises(ThresholdSharingError, match="multiple of"):
        split_secret(b"\x01" * 17, threshold=2, participants=3)
    with pytest.raises(ThresholdSharingError, match="must not be empty"):
        split_secret(b"", threshold=2, participants=3)
    with pytest.raises(ThresholdSharingError, match="index must be positive"):
        VssShare(index=0, limbs=(1,))


def test_duplicate_share_indices_cannot_interpolate():
    shares, commitment = split_secret(SEED, threshold=3, participants=5)
    with pytest.raises(ThresholdSharingError, match="duplicate share indices"):
        reconstruct([shares[0], shares[0], shares[1]], threshold=3, commitment=commitment)


def test_sharing_is_randomised_between_invocations():
    """No hidden default seed. Two splits of one secret must differ.

    Guards against repeating the defect where garbling secrets derived from a
    hardcoded default, making two independent parties produce identical
    material.
    """

    first, first_commitment = split_secret(SEED, threshold=3, participants=5)
    second, second_commitment = split_secret(SEED, threshold=3, participants=5)

    assert first[0].limbs != second[0].limbs, "shares must not repeat"
    # ...but both commit to the same secret, so the digest is stable.
    assert first_commitment.digest == second_commitment.digest
    assert reconstruct(second[:3], threshold=3, commitment=second_commitment) == SEED


def test_a_share_from_one_sharing_is_rejected_by_another():
    """Cross-sharing confusion must not verify."""

    _first, first_commitment = split_secret(SEED, threshold=3, participants=5)
    second, _second_commitment = split_secret(secrets.token_bytes(32), threshold=3, participants=5)
    assert not verify_share(second[0], first_commitment)
