from __future__ import annotations

"""Executable distinction between coin coupling and witness-computable coupling.

A generic SHVZK simulator may be perfectly coupled to an honest prover at the
level of secret random coins while still being useless for efficient static
witness encryption: the decryptor sees the public transcript prefix and a
witness, not the simulator's hidden coins.

Schnorr's sigma protocol provides a clean example.  At a fixed challenge c, the
simulator chooses z and sets A = zG - cX.  An honest prover with witness w can
produce the identical transcript by choosing nonce k = z - cw.  This is exact
*coin coupling*.  But from public (A, c, X) and w, recovering the simulator's z
requires the discrete logarithm of A.  It is therefore not a public
witness-computable coupling/predictable response.
"""

from dataclasses import dataclass

from .real_secp import G, N, Point, add, base_multiply, multiply, negate


class CoupledSHVZKError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SchnorrStatement:
    witness: int
    schema: str = "ranklock-schnorr-statement-v1"

    def __post_init__(self) -> None:
        witness = int(self.witness) % N
        if witness == 0:
            raise CoupledSHVZKError("Schnorr witness must be nonzero")
        object.__setattr__(self, "witness", witness)

    @property
    def public_key(self) -> Point:
        return base_multiply(self.witness)


@dataclass(frozen=True, slots=True)
class SchnorrTranscript:
    commitment: Point
    challenge: int
    response: int

    def __post_init__(self) -> None:
        challenge = int(self.challenge) % N
        response = int(self.response) % N
        if self.commitment is None or challenge == 0 or response == 0:
            raise CoupledSHVZKError("invalid Schnorr transcript")
        object.__setattr__(self, "challenge", challenge)
        object.__setattr__(self, "response", response)

    def verifies(self, public_key: Point) -> bool:
        # zG = A + cX
        return base_multiply(self.response) == add(
            self.commitment,
            multiply(public_key, self.challenge),
        )


def simulate_fixed_challenge(
    public_key: Point,
    *,
    challenge: int,
    simulated_response: int,
) -> SchnorrTranscript:
    c = int(challenge) % N
    z = int(simulated_response) % N
    if public_key is None or c == 0 or z == 0:
        raise CoupledSHVZKError("invalid simulator input")
    commitment = add(base_multiply(z), negate(multiply(public_key, c)))
    if commitment is None:
        raise CoupledSHVZKError("simulated commitment is infinity")
    transcript = SchnorrTranscript(commitment, c, z)
    if not transcript.verifies(public_key):  # pragma: no cover - defense in depth
        raise CoupledSHVZKError("simulator produced a rejecting transcript")
    return transcript


def honest_transcript(
    statement: SchnorrStatement,
    *,
    challenge: int,
    nonce: int,
) -> SchnorrTranscript:
    c = int(challenge) % N
    k = int(nonce) % N
    if c == 0 or k == 0:
        raise CoupledSHVZKError("invalid honest-prover coins")
    transcript = SchnorrTranscript(
        base_multiply(k),
        c,
        (k + c * statement.witness) % N,
    )
    if not transcript.verifies(statement.public_key):  # pragma: no cover
        raise CoupledSHVZKError("honest transcript rejected")
    return transcript


def coupled_honest_nonce(
    statement: SchnorrStatement,
    simulated: SchnorrTranscript,
) -> int:
    nonce = (simulated.response - simulated.challenge * statement.witness) % N
    if nonce == 0:
        raise CoupledSHVZKError("coupled nonce is zero")
    return nonce


@dataclass(frozen=True, slots=True)
class CouplingAudit:
    statement: SchnorrStatement
    challenge: int
    simulated_response: int
    schema: str = "ranklock-coupled-shvzk-audit-v1"

    @property
    def simulated(self) -> SchnorrTranscript:
        return simulate_fixed_challenge(
            self.statement.public_key,
            challenge=self.challenge,
            simulated_response=self.simulated_response,
        )

    @property
    def honest_with_coupled_coins(self) -> SchnorrTranscript:
        simulated = self.simulated
        return honest_transcript(
            self.statement,
            challenge=simulated.challenge,
            nonce=coupled_honest_nonce(self.statement, simulated),
        )

    @property
    def exact_coin_coupling(self) -> bool:
        return self.simulated == self.honest_with_coupled_coins

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "simulated_transcript_accepts": self.simulated.verifies(
                self.statement.public_key
            ),
            "exact_coin_coupling": self.exact_coin_coupling,
            "public_witness_recovery_of_simulated_response": False,
            "recovery_barrier": (
                "Given only (A, c, X) and witness w, the simulator response is "
                "z = log_G(A) + c*w.  Coin coupling exposes a map only when the "
                "simulator's hidden response z is already known; it does not give the "
                "decryptor a public witness-only recovery algorithm."
            ),
            "conclusion": (
                "Exact simulator/prover coin coupling is insufficient.  RankLock needs "
                "witness-computable coupling (a predictable argument/WPRF-like token) "
                "or a concrete LVA-WE gadget."
            ),
        }


def coupled_shvzk_frontier() -> dict[str, object]:
    audit = CouplingAudit(
        SchnorrStatement(0x123456789ABCDEF),
        challenge=0xA5A5A5A5A5A5,
        simulated_response=0xDEADBEEF123456789,
    )
    return {
        "schema": "ranklock-coupled-shvzk-frontier-v1",
        "toy_audit": audit.document(),
        "required_property": {
            "name": "witness-computable transcript coupling",
            "interface": (
                "Recover(instance, witness, verifier_coins, public_prefix) -> the same "
                "laconic prover token selected by setup, without simulator secret coins"
            ),
            "security_role": (
                "The recovered token can key a fixed per-deposit fault secret while "
                "remaining computationally unavailable on NO instances."
            ),
        },
        "novelty_warning": (
            "Predictable arguments and witness encryption are already known to be "
            "equivalent in general.  A paper contribution would require a concretely "
            "efficient construction for the RankVM/one-sided-wrapper relation under "
            "standard pairing assumptions."
        ),
        "breakthrough_target_met": False,
    }
