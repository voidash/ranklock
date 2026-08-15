# Why Reusable Low-Rank KZG Headers Leak

## Safe statement-specific KZG opening lock

For a KZG opening \(C-y=[q(\tau)]_1(\tau-z)\), a statement-specific header can publish

\[
[r(\tau-z)]_2.
\]

The witness \([q(\tau)]_1\) derives the same pairing session as setup. This does not expose \(r[1]_2\) by itself.

## Tempting reusable expansion

To support arbitrary future \(z\), one might publish

\[
[r\tau]_2,\qquad [r]_2,
\]

and derive

\[
[r(\tau-z)]_2=[r\tau]_2-z[r]_2.
\]

But \([r]_2\) is also exactly what is needed to pair the public statement element \(C-y\):

\[
e(C-y,[r]_2).
\]

The session is then public after the future statement exists. The ciphertext can be opened without the KZG witness.

## Executable attack

`test_low_rank_kzg_anchor_expansion_leaks_session` constructs this break with real BN254 arithmetic. The attack is also captured by the general statement-span decomposition routine in `split_basis_ppe_we.py`.

## Consequence

A public low-rank header may compress witness bases only when its span does not also provide a public route to the statement-side session. Generic public-correlation compression is therefore insufficient; the statement and witness bases must be algebraically separated.
