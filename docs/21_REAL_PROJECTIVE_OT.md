# Real OT-to-Projective Input Path

## Result class

**REPRODUCED executable cryptographic prototype.**

The ideal vector-OLE interface from v0.14 has been replaced by a concrete binary-OT transcript over secp256k1. The protocol supplies, for each future byte `v_i`, one scalar

```text
t_i = q_i + v_i b_i  (mod n).
```

Public points satisfy

```text
Q_i = -b_i P_i
U_i =  q_i P_i
```

and setup publishes one common scaling by `s`. Consequently a selected witness satisfies

```text
Σ_i (t_i sP_i + v_i sQ_i) = s Σ_i U_i.
```

The right-hand side is fixed before the future byte vector exists, so it can protect one static 32-byte share.

## Concrete 132-byte run

`results/real_projective_vole.json` records:

```text
future bytes:                         132
binary OTs:                         1,056
public lock excluding OT offers:    73,674 B
OT offers:                          39,072 B
runtime requests:                   39,072 B
runtime responses:                 105,600 B
complete public + interactive:     257,418 B
receiver-local witness:              4,356 B
share recovered:                       yes
```

The reference run uses real secp256k1 group operations, ChaCha20-Poly1305, strict compressed-point parsing, transcript-bound DLEQ proofs, and one-shot sender/receiver state.

## Security boundary

The current binary OT is a Chou–Orlandi-style measurement backend. It is online and is not claimed to provide the final malicious-receiver-secure, noninteractive projectivization theorem required by RankLock. Duty-Free-Bits supplies the relevant vector-VOLE-to-OT direction; a faithful implementation and proof-level mapping remain open.

Every affine state is one-shot. Two distinct evaluations under one coordinate recover `(q_i,b_i)` and permit arbitrary selected-scalar synthesis. Abort, timeout, restart, or replay must therefore burn the complete state.

## Source

- `src/ranklock/real_secp.py`
- `src/ranklock/co_ot.py`
- `src/ranklock/projective_vole_lock.py`
- `tests/test_real_secp.py`
- `tests/test_co_ot.py`
- `tests/test_projective_vole_lock.py`
