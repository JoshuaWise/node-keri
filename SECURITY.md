# Security notes

This library is a cryptographic identity state machine. Its security rests on a small set of invariants enforced on every code path. This document states them, the trust model they assume, and the responsibilities left to the caller.

## Trust model

The library trusts **nothing it is given** for verification. `verifyKel` reconstructs an identifier's state purely by replaying its key event log from inception; every digest, signature, sequence number, previous-event link, and rotation commitment is recomputed and checked against state derived only from earlier events.

A `KeriState` is trusted **only** when it was produced by `verifyKel`, by `resolveDid`, or by this library's own event constructors within the same process. A `KeriState` reconstructed from an external source must not be trusted — pass the events through `verifyKel` instead.

## Security invariants

The verifier enforces all of the following. Each is exercised by the `tamper` and `negative` test suites.

1. **No out-of-profile event is accepted.** Any excluded feature (multisig, witnesses, configuration traits, unknown fields) fails closed with `UNSUPPORTED_FEATURE`. A non-transferable identifier's KEL ends at its inception event — it commits to no next key — so any rotation or interaction appended to it fails closed with `NON_TRANSFERABLE_NOT_EXTENSIBLE`. See [PROFILE.md](./PROFILE.md).
2. **No unknown cryptographic derivation code is accepted.** CESR primitives outside the supported table are rejected with `INVALID_CESR_CODE`.
3. **No event digest is trusted without recomputation.** The self-addressing digest is recomputed from the canonical event and compared.
4. **No signature is trusted without verification** against the key the replay-derived state says is authoritative at that point in the log.
5. **No rotation is accepted unless the revealed key reproduces the prior next-key commitment.** This is KERI pre-rotation: a rotation cannot be forged by an attacker who compromises only the current signing key.
6. **No event is accepted out of order.** Sequence numbers must increment by exactly one, and each event's `p` must equal the previous event's digest.
7. **No caller-supplied state is trusted for verification.**
8. **No DID document is produced from an unverified KEL.** `createDidDocument` consumes only a verified `KeriState`; `resolveDid` verifies first.

## Pre-rotation

Inception and every rotation commit to the _digest_ of the next signing key, not the key itself. The next key is disclosed only when it is used. An attacker who compromises the current signing key still cannot perform a valid rotation: they do not hold the pre-image of the committed next-key digest, and a rotation revealing any other key fails invariant 5. Keep the next keypair's private half at least as well protected as the current one — it is the identifier's recovery path.

## Error policy

Throwing is reserved for **programmer errors**: malformed arguments, a bad key object, an unsupported algorithm requested directly. Anything that can legitimately arrive from an untrusted source — a malformed DID, a tampered, reordered, truncated, mis-framed, or hostile KEL, a bad signature — is returned as a typed result (`{ ok: false, error }`) or, for `verifySignatureWithDid`, as `false`. `verifyKel` never throws on hostile input: a KEL is supplied as a CESR stream, and even a stream that is not well-framed is reported as a `MALFORMED_STREAM` result rather than an exception. A caller must therefore check the result discriminant rather than relying on exceptions.

## Key handling

- Private keys are held as opaque `KeyObject` wrappers. The raw private seed is never exposed by the public API and never appears in any JSON output.
- The only supported operation on a private key is `sign`.
- `createIdentifier` and `rotateIdentifier` reject reusing one key as both the current and the next key — doing so defeats pre-rotation.
- Digest equality during verification uses a constant-time comparison.
- Key generation and any random bytes come from the platform CSPRNG (`node:crypto`); the library makes no randomness policy decisions of its own.

## Caller responsibilities

The library does no I/O. The caller must:

- **Store private keys securely.** Both the current and the next private key matter; losing the next key forfeits the ability to rotate.
- **Persist and transmit the KEL** with integrity. Tampering is _detected_ by `verifyKel`, but availability and ordering of delivery are the caller's concern.
- **Authenticate the binding** between a DID and a KEL out of band, or accept whatever KEL is supplied — this library verifies a KEL's internal consistency and its derivation of the claimed AID, not its provenance.
- **Apply authorization policy.** The library answers "is this event cryptographically valid?", never "is this actor allowed to do this?".

## Reporting

Submit security reports as GitHub issues.
