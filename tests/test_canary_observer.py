from hashlib import sha256

from ranklock.canary_observer import CanaryObserver


def test_canary_records_matches_and_mismatches_without_authority(tmp_path):
    observer = CanaryObserver(tmp_path / "canary.sqlite")
    context = sha256(b"context").digest()
    request = sha256(b"request").digest()
    first = observer.compare(
        context_digest=context,
        request_digest=request,
        ranklock_output=b"same",
        reference_output=b"same",
    )
    second = observer.compare(
        context_digest=context,
        request_digest=sha256(b"request-2").digest(),
        ranklock_output=b"left",
        reference_output=b"right",
    )
    assert first.matched and not second.matched
    assert observer.verify_chain()
    assert observer.summary == {
        "observations": 2,
        "matches": 1,
        "mismatches": 1,
        "audit_chain_valid": True,
        "authoritative": False,
    }
    assert not hasattr(observer, "sign")
    assert not hasattr(observer, "authorize")
