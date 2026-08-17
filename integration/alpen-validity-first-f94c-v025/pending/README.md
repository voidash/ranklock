# Pending Rust changes, not yet in the installer

Work verified against the patched tree but **not yet ported into
`apply_validity_first.py`**, so it is not part of the deliverable. Anything
here must be ported and re-verified from a pristine clone before it counts.

## `p4-complete.diff` — LANDED

This delta is now applied by `apply_validity_first.py` and is part of the
deliverable. The file is kept because the installer applies it directly.

Verified from a pristine clone: preflight clean, apply clean, 31 modified +
4 new matching the declared scope, `cargo fmt --all -- --check` clean, and
`strata-bridge-sm` **450 passed / 0 failed** including
`an_ack_txid_without_the_committed_preimage_is_rejected`.

### How to regenerate it, if it ever needs changing

This took three attempts; the constraint is not obvious.

The diff must be taken **against an already-installed-and-formatted tree**,
and applied **after** `format_touched`:

```
git clone --local <base> /tmp/p4base && cd /tmp/p4base
git checkout f94c06d0...
python3 apply_validity_first.py /tmp/p4base      # installs and formats
cp -r /tmp/p4base /tmp/p4work                    # make the P4 edits in p4work
cargo fmt --all                                  # in p4work
cd <parent> && diff -ruN p4base/crates p4work/crates > p4-complete.diff
```

Two ways that do **not** work, both tried:

- A `git diff` against the pristine base carries the entire installer as
  context, so nothing matches mid-stream.
- A diff from a long-lived scratch clone carries formatting the installer
  never produces; five of six files applied and `tx_classifier.rs` did not.

Also note `diff --label` collapses the per-file paths and `git apply` then
reports "unable to find filename in patch". Use relative paths from a common
parent with `-p1`.

### Porting: attempted, one file short

The installer now carries `patch_p4_ack_witness_check`, but it is **not wired
into `main`**, deliberately. Wiring it in as-is aborts every install.

What was learned:

- The delta must run **after** `format_touched`, not alongside the
  anchor-based edits. The diff was generated from a formatted tree, so its
  context only matches once the earlier edits are normalised. Applied
  mid-stream, four of six files failed.
- Moved after formatting, five of six apply. `tx_classifier.rs` still fails
  at hunk `:12` -- the source tree it was generated from
  (`work/strata-p2pverify`) has accumulated formatting that differs from the
  installer's own output.

**The fix is one cycle:** install onto a pristine clone, let it format, apply
the P4 changes to *that* tree, regenerate `p4-complete.diff` from it, then
wire the call in after `format_touched` and re-verify. Do not regenerate from
`strata-p2pverify`; that is what produced the mismatch.

Remember to raise `EXPECTED_CHANGED_FILES` to 32 and the description string
when it lands (it was set back to 29 when this was unwired).

### Original porting checklist

1. Add `patch_p4_ack_witness_check` to the installer, following
   `patch_base_logging_defect` as the model for a labelled delta.
2. Add the six touched files to `TOUCHED_RUST_FILES`.
3. Raise `EXPECTED_CHANGED_FILES` in `scripts/run_v0252_strata_build_matrix.py`
   (currently 29) and the matching description string.
4. Verify from a pristine clone: preflight, apply, scope count,
   `cargo fmt --all -- --check`, then the bridge-sm suite.
