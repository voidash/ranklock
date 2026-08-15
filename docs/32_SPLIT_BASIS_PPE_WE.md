# Split-Basis Pairing-Product Conditional Disclosure

## Status

**Real BN254 prototype; incomplete security theorem.**

The v0.16 checkpoint treated a nonidentity fixed GT target as mandatory. v0.17 corrects that criterion. A pairing-product relation may be written as

\[
\prod_{i=1}^{m}e(W_i,B_i)=\prod_{\ell=1}^{s}e(S_\ell,D_\ell),
\]

where the future witness elements \(W_i\in G_1\), the witness-side bases \(B_i\in G_2\), and the statement-side terms \((S_\ell,D_\ell)\) are fixed by the relation.

Assume

\[
B_i=\sum_{j=1}^{k}a_{ij}U_j.
\]

Setup samples \(r\) and publishes only \(rU_1,\ldots,rU_k\). A future witness computes

\[
K_W=\prod_{j=1}^{k}e\left(\sum_i a_{ij}W_i,rU_j\right).
\]

Setup computes

\[
K_S=\left(\prod_\ell e(S_\ell,D_\ell)\right)^r.
\]

A satisfying witness gives \(K_W=K_S\).

## Correct security criterion

The normalized PPE target may be identity. What matters is whether the statement-side session has a publicly computable preimage over the **scaled witness-anchor span**.

If every statement base has a known decomposition

\[
D_\ell=\sum_j d_{\ell j}U_j,
\]

then anyone can compute

\[
K_S=\prod_j e\left(\sum_\ell d_{\ell j}S_\ell,rU_j\right)
\]

without a witness. That is a complete disclosure break.

Thus the load-bearing condition is **basis/session separation**, not merely \(T\neq1\).

## Executable evidence

`split_basis_ppe_we.py` uses actual BN254 group and pairing arithmetic. Tests establish:

- direct and rank-compressed witness evaluation agree;
- a satisfying witness recovers the protected value;
- a changed witness fails authenticated decryption;
- tampered scaled anchors fail the same-scalar setup proof;
- standard KZG-opening WE is a one-term special case;
- exposing a statement-base decomposition over scaled anchors recovers the session without the witness.

The 11-term, rank-2 reference has exact prototype accounting in `results/split_basis_ppe.json`.

## Not yet established

- adaptive extractable witness-encryption security;
- knowledge soundness of a complete RankVM wrapper;
- malicious distributed setup;
- a real LVA-to-WE compiler for the fixed wrapper relation;
- production timing or constant-time implementation.
