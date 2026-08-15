# 10 — Reproducibility

## Supported snapshot

```text
RankLock v0.23.0
Python >= 3.11
Dependencies: numpy >= 2.0, cryptography >= 46
```

This repository is variable-time research code. Reproduction validates executable models, exact byte artifacts, attacks and claim boundaries; it does not establish production security.

## Install

```bash
python -m pip install -e .
```

## Reproduce the current retained object

```bash
PYTHONPATH=src python scripts/generate_v023_mask_fusion_results.py
PYTHONPATH=src python scripts/verify_v023_retained_object.py
```

Expected deterministic identities:

```text
compact 91-prime DFB program / slot:       497,718 bytes
fused final masks / slot:                   24,384 bytes
complete slot:                             522,102 bytes
two independent slots:                  1,044,204 bytes
signed positive-lock manifest:                748 bytes
complete retained object:                1,044,952 bytes
margin below one MiB:                         3,624 bytes
retained-object SHA-256:
6d2a20d1a7f5a98531511f230e7b8444dc8e19c92e77ae941a71cb5a885af212
conditional maps verified / slot:               256
public replay without generator state:          true
output equals direct [r]A:                       true
```

The generator executes the full 91-prime path twice, emits two independently seeded slots, reparses the complete object and replays both slots from retained bytes plus future input-label fixtures.

## Historical standalone baseline

```bash
PYTHONPATH=src python scripts/generate_v022_results.py
```

The v0.22 baseline retains one CRT output mask for each of 3,077 affine outputs. It remains useful for checking that v0.23's raw-label fusion preserves the same Embryo result.

## Complete test suite

Heavy pure-Python pairing files can contend in one monolithic process. The supported release protocol uses six deterministic shards, with every test file in its own subprocess:

```bash
for i in 0 1 2 3 4 5; do
  PYTHONPATH=src python scripts/run_test_files.py \
    --workers 2 --timeout 180 \
    --shard-index "$i" --shard-count 6 \
    --json "results/v023_test_shard_${i}.json"
done
```

Verified v0.23 source baseline:

```text
76 test files
299 tests passed
0 failed
1 designated heavy regeneration fixture skipped
```

The skipped test is the full-size 91-prime regeneration fixture. The release generator above executes that path twice and verifies both emitted slots.

## One-command reproduction

```bash
./scripts/reproduce.sh
```

This compiles the tree, runs each test file in isolation, regenerates the v0.22 standalone baseline and v0.23 mask-fused retained object, verifies the retained object, refreshes the v0.18 historical checkpoint, and parses all load-bearing JSON files.

For constrained runtimes, set:

```bash
RANKLOCK_TEST_WORKERS=3 ./scripts/reproduce.sh
```

## Integrity verification

```bash
sha256sum -c MANIFEST.sha256
```

The manifest excludes itself, `SHA256SUMS`, interpreter caches, pytest caches and archive containers.

## Current decision files

```text
README.md
V023_CHECKPOINT.md
V023_RELEASE_NOTES.md
docs/55_V023_MASK_FUSION.md
results/v023_mask_fusion_retained_object.json
results/v023_retained_object_verification.json
STATUS.json
```

Expected decision:

```text
breakthrough_target_met = false
real DFB/Embryo execution = complete
q=2 executable retained-storage target = met by 3,624 bytes
production security / Alpen replacement target = not met
primary next gate = P0-FUSION-PROOF-1
```

## Lineage

```text
v0.13 -> v0.13.2 -> v0.14 -> v0.15 -> v0.16 -> v0.17 -> v0.18 -> v0.19 -> v0.20 -> v0.21 -> v0.22 -> v0.22.1 -> v0.23
```

Earlier documents remain evidence for prior attacks and decisions; their byte claims are not automatically current.
