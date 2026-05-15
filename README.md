# keri

A pure, synchronous TypeScript library for the **KERI identity lifecycle**:
self-certifying `did:keri` identifiers, an append-only key event log (KEL),
key rotation with pre-rotation, interaction events, replay verification, and
W3C DID document generation.

It is a **deterministic state-machine library**, not an agent framework. It
has no dependencies, performs no I/O, and is entirely synchronous. The caller
owns storage, networking, and publication; the library owns the cryptographic
lifecycle. The supported subset is the **KERI Direct JSON Profile v1** — see
[PROFILE.md](./PROFILE.md) for the exact conformance boundary and
[SECURITY.md](./SECURITY.md) for the trust model and security invariants.

> Requires Node.js v20.13.x or later (for the `node:crypto` Ed25519 API).

## Installation

```sh
npm install node-keri
```

## Basic usage

### Create an identifier

```ts
import { createIdentifier } from 'node-keri';

const id = createIdentifier();
// id.did             -> "did:keri:I..."
// id.currentKeyPair  -> current signing keypair (store the private half)
// id.nextKeyPair     -> pre-rotation keypair    (store the private half)
// id.inceptionEvent  -> the signed inception event (the start of the KEL)
// id.state           -> the identifier's state at sequence 0
```

`createIdentifier` generates fresh Ed25519 keypairs unless you supply them.
**You are responsible for storing the returned key material** — the library
keeps no state of its own.

### Rotate the signing key

Rotation reveals the key that inception (or the previous rotation)
*pre-committed* to, and commits to a fresh next key:

```ts
import { rotateIdentifier, generateKeyPair } from 'node-keri';

const nextKeyPair = generateKeyPair();
const rotation = rotateIdentifier({
    state: id.state,
    currentPrivateKey: id.nextKeyPair.privateKey, // the pre-rotated key
    nextKeyPair,
});
// rotation.rotationEvent -> append this to the KEL
// rotation.state         -> state at sequence 1
```

### Anchor data with an interaction event

```ts
import { createInteractionEvent } from 'node-keri';

const ixn = createInteractionEvent({
    state: id.state,
    currentKeyPair: id.currentKeyPair,
    data: [{ capabilityHash: '...' }],
});
```

### Verify a key event log

`verifyKel` replays a KEL from inception and returns the only `KeriState` a
caller may treat as trusted. It never throws for a malformed, tampered, or
hostile KEL — those are returned as a typed `{ ok: false, error }` result:

```ts
import { verifyKel } from 'node-keri';

const result = verifyKel({ aid: id.aid, events: kel });
if (result.ok) {
    console.log(result.state.currentPublicKey);
} else {
    console.error(result.error.code); // e.g. 'INVALID_SIGNATURE'
}
```

### Resolve a DID and produce a DID document

```ts
import { resolveDid, createDidDocument } from 'node-keri';

const resolution = resolveDid({ did: id.did, kel });
if (resolution.ok) {
    const doc = resolution.didDocument; // W3C DID document
}

// Or, from an already-verified state:
const doc = createDidDocument({ state: result.state });
```

### Verify an agent-to-agent message

```ts
import { verifySignatureWithDid } from 'node-keri';

const ok = verifySignatureWithDid({
    did: senderDid,
    kel: senderKel,
    payload,    // Uint8Array of the signed bytes
    signature,  // CESR-qualified Ed25519 signature
});
```

This verifies the KEL, extracts the latest authoritative key, and checks the
signature in one step. It returns `false` for any data-level failure.

## Public API

| Function                  | Purpose                                              |
| ------------------------- | ---------------------------------------------------- |
| `generateKeyPair`         | Generate a fresh Ed25519 keypair.                    |
| `createIdentifier`        | Mint a new `did:keri` identifier and inception event.|
| `rotateIdentifier`        | Roll the signing key forward (pre-rotation).         |
| `createInteractionEvent`  | Anchor data without rotating keys.                   |
| `verifyKel`               | Replay and verify a KEL; reconstruct trusted state.  |
| `parseDidKeri`            | Strict, offline `did:keri` parser.                   |
| `formatDidKeri`           | Build a `did:keri` DID from an AID.                  |
| `resolveDid`              | Verify a caller-supplied KEL, then project a document.|
| `createDidDocument`       | Project a verified state into a W3C DID document.    |
| `exportPublicKey`         | Export a public key as a JWK for sharing.            |
| `verifySignatureWithDid`  | Verify a payload signature against a DID's latest key.|

The error policy is uniform: **throwing is reserved for programmer errors**
(bad arguments, malformed key objects). Anything that can legitimately arrive
from an untrusted source is reported as a typed result, never thrown.

## Error model

- `verifyKel` / `resolveDid` return a discriminated `{ ok }` result. On
  failure, `error.code` is one of the `KeriVerificationError` codes
  (`EMPTY_KEL`, `INVALID_SIGNATURE`, `INVALID_NEXT_KEY_COMMITMENT`,
  `UNSUPPORTED_FEATURE`, …).
- `verifySignatureWithDid` returns a plain `boolean`.
- Programmer errors throw a typed `KeriError` subclass: `InvalidArgumentError`,
  `UnsupportedAlgorithmError`, `MalformedInputError`, `CanonicalJsonError`.

## What this library does not do

No storage, no networking, no discovery, no agent runtime, no registries, no
filesystem access. It builds and verifies events; transport and persistence
are the caller's responsibility.
