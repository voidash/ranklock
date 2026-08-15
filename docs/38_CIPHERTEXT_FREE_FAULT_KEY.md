# Ciphertext-Free Fault-Key Derivation

## Previous activation problem

A conventional conditional lock stores an encrypted 32-byte fault-secret share. A malicious setup contributor may publish valid scaled anchors and a valid same-scalar proof while substituting an unrelated ciphertext. The graph funds successfully, but a future valid witness cannot unlock the intended Bitcoin key.

## New construction

Do not encrypt a payload. Let the accepting pairing session be \(K\). Derive

\[
t=\mathsf{HashToSecpScalar}(K,\mathsf{relationDigest},\mathsf{epoch},\mathsf{signerId}).
\]

Setup publishes the corresponding secp256k1 point

\[
P=tG.
\]

A future satisfying witness reconstructs \(K\), derives \(t\), and checks \(tG=P\). No ciphertext exists to substitute.

## Executable evidence

`ciphertext_free_fault_key.py` combines real BN254 pairing sessions with real secp256k1 arithmetic. Tests show:

- the accepting witness recovers the exact scalar committed by the published point;
- a changed witness does not derive the published key;
- relation, epoch, and signer identifiers domain-separate keys;
- the visible activation relation rejects a wrong setup scalar or substituted public key;
- an n-of-n committee can aggregate context-bound shares into a BIP340-normalized x-only key in the research model.

## Important caveats

- SHA-256 hash-to-scalar is a research model and needs a formally specified production construction;
- the committee aggregation is MuSig-style and not claimed to implement BIP327 exactly;
- public activation still needs a zero-knowledge proof;
- one honest hidden setup scalar protects pre-witness secrecy, while all n-of-n shares are required for liveness.
