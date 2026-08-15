# Static Fixed-Relation Lift

## Central positive result

The post-statement encapsulator disappears when future objects are moved from the witness-encryption **statement** into the **witness** of one relation fixed during setup.

The executable relation is

```text
input authentication:
    Σ_i (t_i P_i + v_i Q_i) = T_input

fixed trace relation:
    Σ_j w_j R_j = T_trace

combined:
    Σ_i (t_i P_i + v_i Q_i) + Σ_j w_j R_j
        = T_input + T_trace.
```

The ciphertext and relation key are generated before either the future bytes or trace witness exists. The one-shot OT path later supplies `(v_i,t_i)`. A correct trace witness completes the same fixed inner-product relation.

## Concrete evidence

- one static 48-byte authenticated ciphertext;
- no post-statement secret holder;
- real secp256k1 relation and DLEQ-verified key;
- real OT-derived future byte witness;
- changed byte, changed selected scalar, missing trace, or altered trace fails;
- exact 132-byte + 64-scalar serialized model: **134,604 bytes** after setup-proof batching.

The full-width result is exact byte accounting from the concrete serialization law. The included runtime benchmark uses a smaller relation because the variable-time Python implementation would otherwise measure hundreds of arbitrary-base scalar multiplications rather than protocol structure.

## Critical limitation

The trace predicate in this module is linear and intentionally toy-sized. It is not RankVM invalidity. The publishable problem is now:

> compile the complete invalidity proof into a fixed linearly verifiable relation whose relation-specific key/CRS remains below the residual byte budget.

## Source

- `src/ranklock/static_linear_conjunction.py`
- `src/ranklock/inner_product_we.py`
- `src/ranklock/batched_inner_product_we.py`
- `tests/test_static_linear_conjunction.py`
- `tests/test_batched_inner_product_we.py`
