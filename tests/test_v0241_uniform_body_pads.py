from __future__ import annotations

import numpy as np

from ranklock.dfb_real import Ccrh


class _ScriptedCcrh(Ccrh):
    def __init__(self) -> None:
        super().__init__()
        self.lengths: list[int] = []

    def expand_many(self, controls, nonces, output_bytes):  # type: ignore[override]
        self.lengths.append(output_bytes)
        rows = len(np.asarray(controls).reshape(-1, 2))
        assert rows == 1
        if output_bytes == 8:
            words = np.array([0xFFFF_FFFF, 2], dtype="<u4")
        elif output_bytes == 16:
            words = np.array([0xFFFF_FFFF, 2, 4, 5], dtype="<u4")
        else:
            raise AssertionError(f"unexpected stream prefix: {output_bytes}")
        return words.view(np.uint8).reshape(1, output_bytes)


def test_exact_rejection_sampler_retries_only_rejected_members():
    ccrh = _ScriptedCcrh()
    controls = np.zeros((1, 2), dtype=np.uint64)
    pads = ccrh.hash_bulk_pads(controls, np.array([7], dtype=np.uint64), 2, 3)
    # 0xffffffff is outside the largest multiple of 3 below 2^32, while 2
    # succeeds in round one.  Round two supplies 4 -> 1 only for member zero.
    assert pads.tolist() == [[1, 2]]
    assert ccrh.lengths == [8, 16]
