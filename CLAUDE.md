# CLAUDE.md

This file guides Claude Code when working with the "keri" repository.

Below is a practical implementation plan for a **pure, synchronous TypeScript KERI lifecycle library**.

Target profile:

> JSON-only, Ed25519-only, single-controller `did:keri`, CESR text primitives, local KEL creation/replay/verification, key rotation, interaction events, DID document generation. No filesystem, no HTTP, no async, no persistence, no networking.

KERI’s core value comes from self-certifying identifiers plus an append-only key event log whose events establish control provenance and support key rotation; witnesses/OOBI/transport are separable from that core. ([Trust over IP][1])

---

## 1. Package boundary

The library should be a **deterministic state-machine package**, not an agent framework.

It should expose functions that operate on plain data:

```
createIdentifier(...)
rotateIdentifier(...)
createInteractionEvent(...)
verifyKel(...)
resolveDid(...)
createDidDocument(...)
```

The caller handles:

```txt
storage
network transport
HTTPS endpoints
authorization policy
agent registry
DID publication
KEL synchronization
```

The package should never call:

```
fs.*
fetch(...)
http.*
https.*
setTimeout(...)
crypto.randomUUID() // avoid hidden policy decisions
```

It may use:

```
node:crypto
```

for Ed25519 signing, verification, secure random bytes, and hashing.

---

## 2. Supported profile

Call the supported subset something explicit, for example:

```txt
KERI Direct JSON Profile v1
```

### Supported

| Capability                        | Include |
| --------------------------------- | ------: |
| JSON KERI events                  |     Yes |
| CESR text primitives              |     Yes |
| Ed25519 signing keys              |     Yes |
| Self-certifying transferable AIDs |     Yes |
| Single signing key                |     Yes |
| Single next-key commitment        |     Yes |
| Inception events                  |     Yes |
| Rotation events                   |     Yes |
| Interaction events                |     Yes |
| Local KEL replay                  |     Yes |
| DID generation                    |     Yes |
| DID document generation           |     Yes |
| Signature verification            |     Yes |
| Deterministic event digesting     |     Yes |

### Excluded

| Capability                     | Exclude |
| ------------------------------ | ------: |
| Multisig / weighted thresholds |     Yes |
| Witnesses                      |     Yes |
| Watchers                       |     Yes |
| Receipts                       |     Yes |
| OOBI                           |     Yes |
| Delegation                     |     Yes |
| TEL / registries               |     Yes |
| Binary CESR                    |     Yes |
| CBOR / MessagePack             |     Yes |
| HTTP transport                 |     Yes |
| Filesystem storage             |     Yes |

---

## 3. Public API shape

### Core creation

```ts
function generateKeyPair(): KeriKeyPair;

function createIdentifier(input?: {
    currentKeyPair?: KeriKeyPair;
    nextKeyPair?: KeriKeyPair;
    metadata?: Record<string, unknown>;
}): {
    did: DidKeri;
    aid: Aid;
    currentKeyPair: KeriKeyPair;
    nextKeyPair: KeriKeyPair;
    inceptionEvent: string; // CESR stream frame — see "Wire format" below
    state: KeriState;
};
```

This creates:

```txt
current signing key
next pre-rotated key
inception event
initial key state
did:keri identifier
```

KERI’s rotation model depends on pre-rotation: the current event commits to the next key material so future rotation can be verified without trusting the new key alone. ([arXiv][2])

---

### Rotation

```ts
function rotateIdentifier(input: {
    state: KeriState;
    currentPrivateKey: KeriPrivateKey;
    nextKeyPair: KeriKeyPair;
}): {
    rotationEvent: string; // CESR stream frame
    state: KeriState;
};
```

Rules:

```txt
event type must be rotation
sequence number increments by 1
previous event digest must match current state
signing key must match current key
new signing key must match prior next-key commitment
new next-key commitment is stored for future rotation
```

---

### Interaction event

```ts
function createInteractionEvent(input: {
    state: KeriState;
    currentPrivateKey: KeriPrivateKey;
    data?: unknown;
}): {
    interactionEvent: string; // CESR stream frame
    state: KeriState;
};
```

Interaction events allow the identifier to anchor arbitrary state transitions or commitments without rotating keys.

For the agent use case, this could anchor:

```txt
agent capability document hash
policy document hash
service endpoint commitment
model card hash
public metadata version
```

---

### KEL verification

```ts
function verifyKel(input: { aid: Aid; kel: string }):
    | {
          ok: true;
          state: KeriState;
      }
    | {
          ok: false;
          error: KeriVerificationError;
      };
```

This is the most important function.

It should replay from inception to latest event and verify:

```txt
AID derivation
event order
sequence numbers
previous-event digest chain
event self-addressing digest
current signing authority
next-key commitments
signatures
event type validity
unsupported feature rejection
```

KERI’s key-event state machine establishes ordering by chaining each non-inception event to the digest of the previous event. ([identity.foundation][3])

---

### DID resolution

```ts
function parseDidKeri(did: string): ParsedDidKeri;

function resolveDid(input: {
    did: DidKeri;
    kel: string;
}): DidResolutionResult;
```

Resolution should be local only. The caller supplies the KEL.

The library should not try to discover the KEL.

---

### DID document generation

```ts
function createDidDocument(input: {
    did: DidKeri;
    state: KeriState;
    services?: DidService[];
}): DidDocument;
```

Minimal output:

```json
{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
    ],
    "id": "did:keri:...",
    "verificationMethod": [
        {
            "id": "did:keri:...#key-0",
            "type": "JsonWebKey2020",
            "controller": "did:keri:...",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "..."
            }
        }
    ],
    "authentication": ["did:keri:...#key-0"],
    "assertionMethod": ["did:keri:...#key-0"]
}
```

---

## 4. Suggested module layout

```txt
src/
  index.ts

  profile/
    constants.ts
    errors.ts
    feature-gates.ts

  bytes/
    base64url.ts
    compare.ts
    utf8.ts

  crypto/
    ed25519.ts
    hash.ts
    random.ts
    keypair.ts

  cesr/
    codes.ts
    encode.ts
    decode.ts
    counter.ts
    qualified.ts

  event/
    types.ts
    canonical-json.ts
    field-order.ts
    inception.ts
    rotation.ts
    interaction.ts
    digest.ts
    sign.ts
    stream.ts
    verify-signature.ts

  kel/
    state.ts
    replay.ts
    validate-inception.ts
    validate-rotation.ts
    validate-interaction.ts

  did/
    did-keri.ts
    document.ts
    resolver.ts

  api/
    create-identifier.ts
    rotate-identifier.ts
    interact-identifier.ts
    verify-kel.ts

  test-vectors/
    fixtures.ts
```

---

## 5. Data model

### Event types

Keep the event model intentionally narrow.

```ts
type KeriEventType = 'icp' | 'rot' | 'ixn';
```

### Base event

```ts
interface KeriEventBase {
    v: string; // version string
    t: KeriEventType; // event type
    d: string; // self-addressing event digest
    i: string; // identifier / AID
    s: string; // hex sequence number
}
```

### Inception event

```ts
interface InceptionEvent extends KeriEventBase {
    t: 'icp';
    kt: '1'; // signing threshold; MVP supports only 1
    k: [string]; // current public key, CESR-qualified
    nt: '1'; // next threshold; MVP supports only 1
    n: [string]; // next key digest/commitment
    bt: '0'; // witness threshold; MVP must be 0
    b: []; // witnesses; empty
    c: []; // configuration traits; restricted
    a: []; // seals/data; MVP empty or tightly controlled
}
```

### Rotation event

```ts
interface RotationEvent extends KeriEventBase {
    t: 'rot';
    p: string; // previous event digest
    kt: '1';
    k: [string]; // new current public key
    nt: '1';
    n: [string]; // new next key commitment
    bt: '0';
    br: [];
    ba: [];
    a: [];
}
```

### Interaction event

```ts
interface InteractionEvent extends KeriEventBase {
    t: 'ixn';
    p: string;
    a: unknown[];
}
```

### Signed event (in-memory shape)

```ts
interface SignedKeriEvent {
    event: KeriEvent;
    signatures: [CesrIndexedSignature]; // MVP exactly one, at key index 0
}
```

`SignedKeriEvent` is the in-memory representation. On the wire an event is a
**CESR stream frame** — its canonical JSON followed by a `-A` counter and the
indexed signature(s). The high-level API (`createIdentifier`, `verifyKel`, …)
takes and returns the stream form (`string`); `encodeEventFrame` /
`parseSignedEvent` / `parseKel` convert. See "Wire format" below.

---

## 5b. Wire format

A KEL is exchanged as a CESR stream, not a JSON `{ event, signatures }`
wrapper. Each event frame is:

```txt
<event canonical JSON><-A counter><indexed signature>
```

The event's version string `v` declares its byte length, so frames are
self-delimiting; a KEL is its frames concatenated in order, with no separators.
Controller signatures are CESR *indexed* signatures ("Siger", code `A`) carrying
a key index — always 0 in this single-key profile. Detached payload signatures
(`verifySignatureWithDid`) stay non-indexed (`0B`, "Cigar"). A stream that is
not well-framed is rejected by `verifyKel` with `MALFORMED_STREAM`.

---

## 6. Internal state model

```ts
interface KeriStateBase {
    aid: Aid;
    did: DidKeri;
    sequenceNumber: number;
    lastEventDigest: CesrDigest;
    currentPublicKey: CesrPublicKey;
    eventType: KeriEventType;
}

// A transferable identifier pre-rotates, so it carries the next-key commitment.
interface TransferableKeriState extends KeriStateBase {
    transferable: true;
    nextKeyCommitment: CesrDigest;
}

// A non-transferable identifier's KEL is its single inception event: it
// commits to no next key and can never rotate. node-keri verifies these
// (e.g. from keripy) but does not generate them.
interface NonTransferableKeriState extends KeriStateBase {
    transferable: false;
}

type KeriState = TransferableKeriState | NonTransferableKeriState;
```

This is derived by replaying the KEL. It should not be trusted if provided externally unless it was returned by `verifyKel`. Narrow on `transferable` to reach `nextKeyCommitment`.

---

## 7. Canonical JSON

This is a critical module.

You need one deterministic serialization function:

```ts
function canonicalizeJson(value: unknown): Uint8Array;
```

Rules:

```txt
objects emit keys in property (insertion) order, never sorted
no insignificant whitespace
stable number policy
reject NaN, Infinity, -0
reject undefined, functions, symbols
UTF-8 output
arrays preserve order
```

Events are **not** serialized with sorted keys. KERI orders an event's
top-level fields in a fixed, type-specific canonical order — `icp`, `rot`,
and `ixn` each have their own field sequence. `toCanonicalEvent`
(`event/field-order.ts`) rebuilds an event with its fields in that order, and
every digest/signature path serializes through it, so the bytes never depend
on how the event object was constructed or parsed. `canonicalizeJson` itself
preserves the property order it is handed.

For KERI compatibility, this must match the selected KERI JSON serialization rules as closely as possible. If this diverges, digests diverge, and external verification breaks.

Pragmatic MVP choice:

```txt
Only accept event objects produced by this library for signing.
For verification, parse strict JSON and canonicalize before digesting.
Reject unknown event fields unless explicitly allowed by the profile.
```

---

## 8. CESR subset

You still need CESR text primitives, but only a narrow table.

### Implement

```ts
encodePublicKeyEd25519(raw32: Uint8Array): CesrPublicKey
decodePublicKeyEd25519(qb64: string): Uint8Array

// Non-indexed signature ("Cigar", 0B) — for detached payload signatures.
encodeSignatureEd25519(raw64: Uint8Array): CesrSignature
decodeSignatureEd25519(qb64: string): Uint8Array

// Indexed signature ("Siger", A) — the form attached to KEL events.
encodeIndexedSignatureEd25519(raw64: Uint8Array, index: number): CesrIndexedSignature
decodeIndexedSignatureEd25519(qb64: string): { raw: Uint8Array; index: number }

// Digests are algorithm-agile. SHA-256 has dedicated helpers; the generic
// pair works for any registered digest code.
encodeDigestSha256(raw32: Uint8Array): CesrDigest
decodeDigestSha256(qb64: string): Uint8Array
encodeDigest(code: string, raw: Uint8Array): CesrDigest
decodeDigest(qb64: string): { raw: Uint8Array; code: string }
```

The `-A` "ControllerIdxSigs" counter is also implemented (`src/cesr/counter.ts`)
— it is the one CESR counter the profile needs, to frame an event's controller
signatures in the wire stream.

### Digest algorithm registry

Keys and signatures are Ed25519-only, but **digests are not pinned to one
algorithm**. KERI digests are self-describing — the CESR derivation code names
the hash — so a KEL may mix algorithms across events. The policy is "any
available 256-bit or 512-bit hash":

- `digestAlgorithms` (`src/crypto/digests.ts`) is an `Object.create(null)` map
  from CESR digest code to `{ name, hash }`. It is exported and
  **monkey-patchable**: a caller can register an algorithm node-keri does not
  ship (e.g. Blake3-256 under code `E`).
- At load it auto-registers every native `node:crypto` hash the linked OpenSSL
  provides (SHA2-256/512, SHA3-256/512, BLAKE2s-256, BLAKE2b-512).
- SHA-256 (`I`) is the hard-coded default for generation; `digestCode` on the
  event constructors and the high-level API overrides it.
- Verification auto-detects each event's algorithm from its own digest code
  and recomputes under exactly that — never KEL-wide pinned.

### Reject

```txt
unknown derivation codes
digest codes with no registered implementation
digest widths other than 256-bit and 512-bit
variable-length groups
counters other than the `-A` controller-signature counter
binary CESR
attached receipts
non-Ed25519 keys
```

This is where strictness helps security. Do not silently accept unsupported
codes — a digest whose algorithm has no registered implementation is rejected,
never assumed.

---

## 9. Crypto module

Use Node’s built-in crypto only.

```ts
import {
    generateKeyPairSync,
    sign,
    verify,
    createHash,
    randomBytes,
    KeyObject,
} from 'node:crypto';
```

Expose opaque key wrappers:

```ts
interface KeriPrivateKey {
    readonly type: 'KeriPrivateKey';
    readonly algorithm: 'Ed25519';
    readonly keyObject: KeyObject;
}

interface KeriPublicKey {
    readonly type: 'KeriPublicKey';
    readonly algorithm: 'Ed25519';
    readonly raw: Uint8Array;
    readonly cesr: CesrPublicKey;
}
```

Security rules:

```txt
never serialize private keys by default
never include private keys in JSON output
never accept raw private key strings casually
zero-copy as little as possible
use timingSafeEqual for digest comparison
throw typed errors, not generic Error
```

---

## 10. Lifecycle flows

### Create identifier

```txt
1. Generate current Ed25519 keypair, unless supplied.
2. Generate next Ed25519 keypair, unless supplied.
3. CESR-encode current public key.
4. Hash/CESR-encode next public key commitment.
5. Construct inception event with placeholder digest.
6. Canonicalize event minus final digest or with dummy digest according to chosen KERI rules.
7. Compute self-addressing event digest.
8. Insert digest.
9. Derive AID from inception event/key material.
10. Sign event.
11. Return DID, event, keypairs, state.
```

### Rotate

```txt
1. Validate provided state.
2. Decode current public key from state.
3. Decode new current public key.
4. Verify new current public key matches prior next-key commitment.
5. Compute new next-key commitment.
6. Construct rotation event with previous event digest.
7. Compute event digest.
8. Sign with old/current private key or required key per selected KERI rule.
9. Return signed rotation event and new state.
```

### Verify KEL

```txt
1. Require first event to be inception.
2. Reject unsupported features immediately.
3. Verify inception AID derivation.
4. Verify inception signature.
5. Build initial state.
6. For each subsequent event:
   - check sequence number
   - check previous digest
   - check event digest
   - check signature against current key
   - if rotation, verify new key matches prior next commitment
   - update state
7. Return final state.
```

---

## 11. Error taxonomy

Use typed discriminated errors.

```ts
type KeriVerificationError =
    | { code: 'EMPTY_KEL' }
    | { code: 'INVALID_DID'; message: string }
    | { code: 'UNSUPPORTED_FEATURE'; feature: string }
    | { code: 'INVALID_EVENT_TYPE'; eventType: string }
    | { code: 'NON_TRANSFERABLE_NOT_EXTENSIBLE'; eventType: string }
    | { code: 'DEACTIVATED_NOT_EXTENSIBLE'; eventType: string }
    | { code: 'INVALID_SEQUENCE'; expected: number; actual: number }
    | { code: 'INVALID_PREVIOUS_DIGEST' }
    | { code: 'INVALID_EVENT_DIGEST' }
    | { code: 'INVALID_SIGNATURE' }
    | { code: 'INVALID_NEXT_KEY_COMMITMENT' }
    | { code: 'INVALID_CESR_CODE'; value: string }
    | { code: 'NON_CANONICAL_EVENT' }
    | { code: 'MALFORMED_STREAM'; message: string };
```

Prefer result objects for verification:

```
{ ok: true, state }
{ ok: false, error }
```

Use throwing only for programmer errors:

```txt
invalid function arguments
malformed key object
unsupported algorithm requested
```

---

## 12. Security invariants

The package should enforce these invariants:

```txt
No event with unsupported features is accepted.
No unknown cryptographic derivation code is accepted.
No rotation is accepted unless the new key matches the previous next-key commitment.
No event is accepted out of order.
No event digest is trusted without recomputation.
No signature is trusted without verification against replay-derived state.
No caller-provided state is trusted for verification.
No DID document is produced from an unverified KEL unless explicitly marked unsafe.
```

Add an API distinction:

```ts
createDidDocumentFromVerifiedState(state);
```

not:

```ts
createDidDocumentFromUntrustedEvents(events);
```

The latter should internally call `verifyKel`.

---

## 13. Testing plan

Minimum test categories:

```txt
CESR encode/decode round trips
invalid CESR code rejection
Ed25519 sign/verify
canonical JSON stability
inception event creation
rotation success
rotation with wrong key fails
interaction event success
event sequence gap fails
previous digest mismatch fails
tampered event fails
tampered signature fails
unknown witness field fails
multisig threshold fails
non-JSON-safe values fail
DID parse/format round trip
DID document generated from latest state
```

Use fixed deterministic vectors for repeatability:

```
const seedFixtureCurrent = ...
const seedFixtureNext = ...
```

Since Node’s Ed25519 API does not naturally expose seed-based deterministic key generation in a simple way, you may need test-only embedded DER keys.

---

## 14. Estimated implementation size

For this exact pure lifecycle library:

| Area                         |         LOC |
| ---------------------------- | ----------: |
| Types and profile gates      |     500–900 |
| Base64url / bytes utilities  |     300–600 |
| CESR subset                  | 1,200–2,500 |
| Crypto wrappers              |   700–1,200 |
| Canonical JSON               |   500–1,000 |
| Event construction/signing   | 1,200–2,000 |
| KEL replay/verification      | 1,800–3,000 |
| DID parser/resolver/document |   900–1,600 |
| Errors/API polish            |   500–1,000 |
| Tests/vectors                | 4,000–8,000 |

Implementation only:

```txt
7.5k–13.8k LOC
```

Including tests:

```txt
12k–22k LOC
```

---

## 15. Milestone plan

### Milestone 1: Foundation

Deliver:

```txt
base64url
strict bytes helpers
canonical JSON
typed errors
Ed25519 key generation/sign/verify
SHA-256 digest
```

Exit criteria:

```txt
all primitive tests pass
no third-party dependencies
all APIs synchronous
```

---

### Milestone 2: CESR subset

Deliver:

```txt
qualified Ed25519 public keys
qualified Ed25519 signatures
qualified SHA-256 digests
strict decoders
```

Exit criteria:

```txt
unknown codes rejected
round-trip vectors pass
malformed lengths rejected
```

---

### Milestone 3: Event creation

Deliver:

```txt
inception event
rotation event
interaction event
event digesting
event signing
```

Exit criteria:

```txt
can create a complete local KEL
can rotate any number of times
can create interaction events
```

---

### Milestone 4: Replay verifier

Deliver:

```txt
verifyKel
state reconstruction
signature validation
sequence validation
digest-chain validation
rotation commitment validation
unsupported feature rejection
```

Exit criteria:

```txt
tampering any event fails
reordering events fails
wrong rotation key fails
latest state is deterministic
```

---

### Milestone 5: DID surface

Deliver:

```txt
did:keri parser
did formatter
DID document generator
local resolver using caller-supplied KEL
```

Exit criteria:

```txt
DID doc reflects latest verified key state
resolution never performs IO
malformed DID rejected
```

---

### Milestone 6: Hardening

Deliver:

```txt
negative test suite
mutation-style tamper tests
API docs
profile conformance notes
security notes
```

Exit criteria:

```txt
profile boundaries are explicit
unsupported KERI features fail closed
public API is stable
```

---

## 16. Recommended public API v1

```ts
export {
    generateKeyPair,
    createIdentifier,
    rotateIdentifier,
    createInteractionEvent,
    deactivateIdentifier,
    verifyKel,
    parseDidKeri,
    formatDidKeri,
    resolveDid,
    createDidDocument,
    exportPublicKey,
    verifySignatureWithDid,
};
```

Where `verifySignatureWithDid` is useful for agent-to-agent communication:

```ts
function verifySignatureWithDid(input: {
    did: DidKeri;
    kel: string; // CESR stream; the empty string '' means "no KEL"
    payload: Uint8Array;
    signature: CesrSignature;
}): boolean;
```

Flow:

```txt
1. Caller receives message over HTTPS.
2. Caller receives or already has the sender DID (+ KEL, if transferable).
3. With a non-empty `kel`: library verifies the KEL and extracts the latest
   public key. With `kel === ''` and a non-transferable DID: the AID *is* the
   key — self-certifying — so the key is read straight from the prefix.
4. Library verifies the message signature against that key.
```

`resolveDid` follows the same `kel: string` convention — pass `''` to resolve a
non-transferable DID straight from its prefix.

That maps cleanly to the agent identity use case.

---

## Bottom line

Build this as a **pure KERI state-machine library**:

```txt
input: keys, events, payloads
output: signed events, verified states, DID documents
```

Do not build:

```txt
storage
networking
discovery
agent runtime
registry
filesystem adapter
```

That keeps the scope realistic while preserving the KERI property actually needed: **a replay-verifiable cryptographic identity lifecycle for agents.**

[1]: https://trustoverip.github.io/kswg-keri-specification/?utm_source=chatgpt.com 'KERI specification'
[2]: https://arxiv.org/abs/1907.02143?utm_source=chatgpt.com 'Key Event Receipt Infrastructure (KERI)'
[3]: https://identity.foundation/keri/kids/kid0008Comment.html?utm_source=chatgpt.com 'KID0008 - Key-Event State Machine - Commentary | keri'
