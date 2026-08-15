# Basis-Separated KZG Experiment

## Construction

The experiment introduces an independent scalar \(\rho\). Commitments use the ordinary monomial basis, while opening witnesses are multiplied by \(\rho\):

\[
\pi=[\rho q(\tau)]_1.
\]

Verification is

\[
e(\pi,[\tau-z]_2)=e(C-y,[\rho]_2).
\]

The witness-side reusable header may contain \([r\tau]_2,[r]_2\) without directly exposing the statement-side \([r\rho]_2\).

## Positive result

The future point \(z\) can be applied publicly to the reusable witness header. The opening verifies and decrypts with actual BN254 arithmetic.

## Remaining timing failure

The payload session still depends on the future statement element \(C-y\) while \(r\) is live. Therefore either:

1. an online encapsulator retains \(r\) until the future statement exists; or
2. setup publishes \([r\rho]_2\), which makes the statement session publicly computable.

So basis separation fixes the immediate span leak but does not by itself produce a static lock for future commitments.

## Decision

**BASIS SEPARATION PASSES; STATIC TIMING REMAINS OPEN.**

The correct response is the fixed-statement witness lift: future inputs, proof elements, and transcript values become witness variables of a relation fixed at activation.
