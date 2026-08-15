# RankLock v0.24.1 release notes

## Reproducibility recovery

v0.24.1 restores a complete source and test tree around the surviving v0.24
artifacts. It adds pinned dependencies, a one-command deterministic reproduction
path, independent public replay, two-run byte comparison, package checksums and
clean-extraction validation.

## Security corrections

- Exact rejection sampling replaces biased reduction for every CRT body pad.
- Two complete slots use disjoint CCRH nonce namespaces.
- The entire program and decoder are sealed under a slot-specific seed.
- Input releases bind context, slot, canonical point, activated root, seed and authorization transaction.
- The BIP340 signature now commits to the entire 512-opening vector, closing an outsider burn/DoS path.
- Authorized attempts burn before semantic opening, seed, parser or evaluator checks.
- The third-point claim is limited to accepted protocol evaluations and an explicit fresh-challenge assumption; raw group linearity is acknowledged.

## Reproduce

```bash
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
./scripts/reproduce_v0241.sh
```

See `REPRODUCE.md` for deterministic and fresh-evidence boundaries.

## Non-claims

This package does not provide malicious-secure distributed setup, Bitcoin-enforced
release/burn semantics, production constant-time code or an independent audit.
It is not safe for funds.
