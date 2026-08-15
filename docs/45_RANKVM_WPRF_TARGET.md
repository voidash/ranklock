# 45 — Hard-YES RankVM witness-PRF target

## Interface

For a fixed program/deposit/epoch context `x`, distributed setup creates a public artifact and commits a 32-byte output. Public evaluation receives:

- the 128-byte future counterproof;
- 36 bytes of public values;
- authentic projective-selection evidence;
- a complete RankVM INVALID witness.

Every accepting witness for `x` must recover the same output.

## Required security game

The statement is already a YES instance before the bridge event because some future invalid counterproof exists. Security must therefore hold on a hard-to-witness YES instance.

The adversary receives:

- the public artifact;
- the state of `n-1` corrupted setup contributors;
- abort/restart transcripts;
- erasure receipts.

It does not receive a complete authenticated INVALID witness. It must be unable to distinguish the fixed output from random or recover the corresponding Bitcoin scalar.

Any successful predictor must yield extraction of:

1. the selected future bytes;
2. their authentication evidence;
3. a complete accepting RankVM-invalidity witness.

## Why existing local-opening WPRFs do not directly solve it

The future input has 1,312 bits. Encoding each possible input as one position in a vector commitment requires a `2^1312` truth table. A single local opening also does not prove a complete RankVM execution.

## Status

No standard-assumption construction meeting this interface is implemented. This remains the cryptographic fallback if the validity-first graph cannot be made acceptable.

Evidence:

- `src/ranklock/rankvm_wprf_target.py`
- `results/v018_rankvm_wprf_target.json`
