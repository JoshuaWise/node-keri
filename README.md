# keri

A pure, synchronous, Node.js library for the **[KERI](https://keri.one/) identity lifecycle**. Create, rotate, deactivate, and verify `did:keri` identifiers using cryptographically verifiable append-only key event logs (KEL).

Basically, KERI let's you create unique [DIDs](https://www.w3.org/TR/did-1.0/) (decentralized identifiers) which are cryptographically bound to a private key. You can rotate your keys without changing your DID, and other people can verify that the new keys are in-fact owned by the same DID owner as the previous keys. All of this is possible without any centralized service or shared blockchain. Even if your current keys are stolen or their crypto algorithm is cracked, you can rotate your keys to regain control of your identity.

> This works by storing the _next_ private key safely offline, or by storing some secret seed offline which is used to deterministically generate all future private keys for the DID

**In practice, this means you can have your own persistent "account" in decentralized, peer-to-peer networks. An obvious use-case is in agent-to-agent communication.**

This is a **deterministic state-machine library**, not an authentication framework. It has no dependencies, performs no I/O, and is entirely synchronous. The caller is responsible for secure storage and networking; the library just owns the cryptographic lifecycle. Not all KERI features are supported; the supported subset is the **KERI Direct JSON Profile v1** — see [PROFILE.md](./PROFILE.md) for the exact conformance boundary and [SECURITY.md](./SECURITY.md) for the trust model and security invariants.

## Installation

```
npm install node-keri
```

> Requires Node.js v20.13.x or later.

## Basic usage

### Create an identifier, rotate it, and store its keys

```ts
import { createIdentifier, rotateIdentifier, generateKeyPair } from 'node-keri';

// You own key management: generate the current signing key and the
// pre-rotation key yourself.
const currentKeyPair = generateKeyPair();
const nextKeyPair = generateKeyPair();

// Mint a new did:keri identifier. createIdentifier takes only the material the
// inception event actually consumes — the current key's *private* half (its
// public half is derived and disclosed) and the next key's *public* half (only
// its digest is committed) — and returns no key material of its own.
const id = createIdentifier({
	currentPrivateKey: currentKeyPair.privateKey,
	nextPublicKey: nextKeyPair.publicKey,
});

// Rotate the signing key: reveal the pre-rotated key, commit to a fresh one.
const rotationKeyPair = generateKeyPair();
const rotation = rotateIdentifier({
	state: id.state,
	currentPrivateKey: nextKeyPair.privateKey, // the key inception pre-committed to
	nextPublicKey: rotationKeyPair.publicKey, // the next pre-rotation commitment
});

// After the rotation, nextKeyPair is the authoritative signing key and
// rotationKeyPair is the new pre-rotation key — keep both private halves.

// Persist the key event log; keep the private keys in your own secure store —
// the library never serializes private keys. Each event is a CESR stream
// frame, so the KEL is just its events concatenated, in order.
const kel = id.inceptionEvent + rotation.rotationEvent;
```

### Sign a message

```ts
import {
	createIdentifier,
	generateKeyPair,
	sign,
	encodeSignatureEd25519,
} from 'node-keri';

const currentKeyPair = generateKeyPair();
const id = createIdentifier({
	currentPrivateKey: currentKeyPair.privateKey,
	nextPublicKey: generateKeyPair().publicKey,
});
const payload = new TextEncoder().encode('a message from the DID controller');

// Sign with the identifier's current private key, then CESR-qualify the
// signature so it is safe to transmit as text.
const signature = encodeSignatureEd25519(sign(currentKeyPair.privateKey, payload));
```

### Verify a signed message

```ts
import { verifySignatureWithDid } from 'node-keri';

// `did`, `kel`, `payload`, and `signature` are supplied by the signer.
const ok = verifySignatureWithDid({
	did: id.did,
	kel: id.inceptionEvent, // the signer's full key event log (a CESR stream)
	payload,
	signature,
});
// ok === true: the signature verifies under the DID's latest key.
```

`verifySignatureWithDid` establishes the DID's authoritative key — by replaying
the KEL for a transferable DID, or reading it straight from the AID for a
self-certifying non-transferable one — and checks the signature in one step. It
returns `false` for any data-level failure — a malformed DID, a non-verifying
KEL, or a bad signature.

## Wire format

Events and KELs are exchanged as **CESR streams** — the form the reference
KERI implementation (keripy) uses on the wire. Each event is one frame: the
event's canonical JSON, followed immediately by an attachment group — a `-A`
counter naming how many controller signatures follow, then the indexed
signatures themselves (a "Siger", CESR code `A`):

```text
{"v":"KERI10JSON0000fb_","t":"icp",...}-AABAA<86 base64 chars>
└──────────── event JSON (size from `v`) ──────────┘└┬─┘└────┬────┘
                                  counter (-A, count 1) ┘     │
                                       one indexed signature ─┘
```

A KEL is simply the frames of its events **concatenated, in order** — there
are no separators. So `createIdentifier`, `rotateIdentifier`, and
`interactIdentifier` each return their event as a frame string, and a KEL is
built with `+`:

```ts
const kel = id.inceptionEvent + rotation.rotationEvent + interaction.interactionEvent;
```

`verifyKel`, `resolveDid`, and `verifySignatureWithDid` all take the KEL in
this string form. To inspect an event's structured shape, parse a frame with
`parseSignedEvent` (or a whole stream with `parseKel`) into a `SignedKeriEvent`;
`encodeEventFrame` is the inverse. The indexed-signature primitives —
`encodeIndexedSignatureEd25519`, `decodeIndexedSignatureEd25519`,
`signatureIndex` — are exported for low-level use.

Detached signatures over arbitrary payloads (as in `verifySignatureWithDid`)
are _not_ indexed: they use the non-indexed `0B` "Cigar" form produced by
`encodeSignatureEd25519`.

## API reference

The error policy is uniform across the whole surface: **throwing is reserved for programmer errors** — a wrong argument type, a malformed key object, an out-of-profile algorithm request. Anything that can legitimately arrive from an untrusted source — a tampered KEL, a malformed DID, a non-verifying signature — is reported as a typed `{ ok: false, error }` result or a `false` return, never thrown. Throwing functions throw a `KeriError` subclass; see [Errors](#errors).

### Identifier lifecycle

#### `createIdentifier()`

```ts
function createIdentifier(input: {
	currentPrivateKey: KeriPrivateKey;
	nextPublicKey: KeriPublicKey;
	establishmentOnly?: boolean;
	digestCode?: string;
}): {
	did: DidKeri;
	aid: Aid;
	inceptionEvent: string;
	state: KeriState;
};
```

Mint a new transferable `did:keri` identifier. You supply the key material, and only the minimum the inception event consumes: `currentPrivateKey` is the current signing key's private half — its public half is derived and disclosed as `k[0]` — and `nextPublicKey` is the pre-rotation key's public half, whose digest is committed as the next-key commitment. Both are **required**. It builds and signs the inception event and returns the DID, the signed event, and the replay-derived sequence-0 state — and **no key material**, since you already hold it. Throws `InvalidArgumentError` if the current and next keys are the same key. **Keep the current private key to sign with and the pre-rotation private key to rotate to later; the library never serializes private keys.**

`inceptionEvent` is the signed event in its **CESR stream** wire form — see [Wire format](#wire-format). A KEL is built by concatenating these event strings in order.

`digestCode` selects the hash algorithm for the inception SAID, AID, and next-key commitment — it defaults to SHA-256 (`I`). See [Digest algorithms](#digest-algorithms).

Set `establishmentOnly: true` to mint an **establishment-only** identifier. It defaults to `false`.

#### `rotateIdentifier()`

```ts
function rotateIdentifier(input: {
	state: KeriState;
	currentPrivateKey: KeriPrivateKey;
	nextPublicKey: KeriPublicKey;
	digestCode?: string;
}): {
	rotationEvent: string;
	state: KeriState;
};
```

Roll the signing key forward. `currentPrivateKey` is the private half of the key being rotated _to_ — the pre-rotation key whose digest the prior event committed; its public half must reproduce that commitment or the rotation is rejected. `nextPublicKey` is the public half of the freshly chosen pre-rotation key for the _next_ rotation — only its digest is committed; keep the matching private half to rotate again later. Returns the signed rotation event and the new state.

`digestCode` selects the hash for this event's SAID and new next-key commitment (default SHA-256). The prior commitment is always re-checked under its _own_ original algorithm, so rotations may switch algorithms freely.

#### `interactIdentifier()`

```ts
function interactIdentifier(input: {
	state: KeriState;
	currentPrivateKey: KeriPrivateKey;
	data?: readonly unknown[];
	digestCode?: string;
}): {
	interactionEvent: string;
	state: KeriState;
};
```

Anchor arbitrary data to the identifier without rotating keys. `currentPrivateKey` must be the currently authoritative signing key. Each `data` entry must be canonical-JSON-serializable. Returns the signed interaction event and the advanced state. `digestCode` selects the hash for the event's SAID (default SHA-256). Throws `InvalidArgumentError` for an establishment-only identifier, which by construction accepts no interaction events.

#### `deactivateIdentifier()`

```ts
function deactivateIdentifier(input: {
	state: KeriState;
	currentPrivateKey: KeriPrivateKey;
	digestCode?: string;
}): {
	deactivationEvent: string;
	state: DeactivatedKeriState;
};
```

Permanently abandon an identifier. Per the `did:keri` method, deactivation is a rotation to zero forward (next) controlling keys: the event is a `rot` with `nt: "0"` and an empty `n`. `currentPrivateKey` is the pre-rotation key being revealed — exactly as for `rotateIdentifier`, its public half must reproduce the prior next-key commitment. Because the event commits to no next key, it is the **final** event of the KEL: `verifyKel` rejects anything appended after it with `DEACTIVATED_NOT_EXTENSIBLE`, and `verifySignatureWithDid` no longer trusts the DID. The returned `state` has `deactivated === true` and `transferable === false`. **This step is irreversible.**

### Signing and verifying

#### `verifyKel()`

```ts
function verifyKel(input: {
	aid: Aid;
	kel: string;
}): { ok: true; state: KeriState } | { ok: false; error: KeriVerificationError };
```

Replay a key event log — a CESR stream — from inception and reconstruct the latest authoritative state. The stream is first parsed into its events (a framing defect is reported as `MALFORMED_STREAM`); then every event's structure, canonical serialization, self-addressing digest, version string, sequence number, previous-event link, rotation commitment, and signature is recomputed and checked, and the inception event must derive exactly `aid`. An event whose wire JSON is not in KERI's canonical field order is rejected as `NON_CANONICAL_EVENT`. **The returned `state` is the only `KeriState` a caller may treat as verified.** Never throws for a malformed or hostile KEL — that is returned as `{ ok: false }`.

`verifyKel` accepts both transferable and non-transferable AIDs. A non-transferable AID — a basic prefix that is the controller's `B`-coded Ed25519 key — has a single-event KEL and cannot rotate; an event appended after its inception is rejected with `NON_TRANSFERABLE_NOT_EXTENSIBLE`. `state.transferable` discriminates the two, and `state.nextKeyCommitment` is present only when it is `true`. node-keri verifies non-transferable AIDs but does not generate them.

A KEL that ends in a deactivation event (see `deactivateIdentifier`) verifies normally, and its `state` has `deactivated === true` and `transferable === false`; any event appended after the deactivation is rejected with `DEACTIVATED_NOT_EXTENSIBLE`.

#### `verifySignatureWithDid()`

```ts
function verifySignatureWithDid(input: {
	did: DidKeri;
	kel: string;
	payload: Uint8Array;
	signature: CesrSignature;
}): boolean;
```

The message verification primitive. Establishes the key `did` makes authoritative and checks `signature` over `payload` against it — in one call. `kel` is always required, but the **empty string** `''` stands for "no KEL":

- With a **non-empty `kel`** (a CESR stream), the key is whatever replaying that KEL yields — it must verify and belong to the DID's AID. A transferable DID can be verified only this way.
- With an **empty `kel`**, the DID must be a **non-transferable** AID: a `B`-coded basic prefix is self-certifying, so the key is read straight from the AID. (A non-transferable identifier may have no KEL at all.)

Returns `false` for every data-level failure: a malformed DID, an empty or non-verifying KEL for a transferable DID, a KEL for a different identifier, a KEL for a deactivated identifier, or a malformed or mismatched signature. `signature` is a non-indexed CESR signature (a "Cigar", code `0B`) — the form for detached signatures over arbitrary payloads.

### DID surface

#### `resolveDid()`

```ts
function resolveDid(input: {
	did: DidKeri;
	kel: string;
}):
	| { ok: true; didDocument: DidDocument; state: KeriState }
	| { ok: false; error: KeriVerificationError };
```

Resolve a `did:keri` DID entirely offline against a caller-supplied KEL: verify the KEL against the DID's AID, then project the verified latest state into a DID document. `state` is the verified latest `KeriState` — the only one the caller may treat as trusted. Any data-level failure is returned as `{ ok: false }`. A deactivated DID still resolves with `ok: true` — its `didDocument` is authority-free (empty `verificationMethod` / `authentication` / `assertionMethod`) and `state.deactivated` is `true`.

A non-transferable DID resolves with the **empty string** `''` for `kel`: it is self-certifying, so the document is projected straight from the prefix. A non-transferable DID may also be resolved from its trivial single-event KEL by passing that stream.

#### `createDidDocument()`

```ts
function createDidDocument(input: {
	state: KeriState;
	did?: DidKeri;
	services?: readonly DidService[];
}): DidDocument;
```

Project a _verified_ `KeriState` into a W3C DID document with a single Ed25519 verification method (`JsonWebKey2020` / `publicKeyJwk`) referenced from both `authentication` and `assertionMethod`. Pass `state` only from `verifyKel` / `resolveDid` or an in-process constructor; `did`, when given, must match `state.did`. Optional `services` are validated and bare-fragment ids are expanded against the document's DID.

### Key handling

#### `KeriKeyPair`

A wrapper type for an Ed25519 keypair.

Access each underlying [`KeyObject`](https://nodejs.org/api/crypto.html#class-keyobject) at:

- `pair.publicKey.keyObject`
- `pair.privateKey.keyObject`

#### `generateKeyPair()`

```ts
function generateKeyPair(): KeriKeyPair;
```

Generate a fresh Ed25519 keypair from the platform [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).

#### `keyPairFromSeed()`

```ts
function keyPairFromSeed(seed: Uint8Array): KeriKeyPair;
```

Reconstruct a keypair from a 32-byte Ed25519 seed.

### Digest algorithms

KERI digests are self-describing — every qualified digest carries a CESR derivation code naming its hash algorithm — so a KEL may mix algorithms across events. This library supports **any available 256-bit or 512-bit hash**.

#### `digestAlgorithms`

```ts
const digestAlgorithms: Record<string, DigestAlgorithm | undefined>;
interface DigestAlgorithm {
	name: string;
	hash(input: Uint8Array): Uint8Array;
}
```

The registry of digest implementations, keyed by CESR derivation code. The value type includes `undefined` because the registry is sparse — indexing an unregistered code yields `undefined` — so every read must handle the absent case. It is a null-prototype object, populated at load with every native `node:crypto` hash the linked OpenSSL provides — SHA2-256 (`I`), SHA2-512 (`0G`), SHA3-256 (`H`), SHA3-512 (`0E`), BLAKE2s-256 (`G`), BLAKE2b-512 (`0F`). A code with no entry is rejected everywhere — decoding, verification, generation — so the library never trusts a hash it cannot recompute.

It is **monkey-patchable**: register an algorithm node-keri does not ship by assigning an entry. The implementation must return 32 bytes for a one-character code or 64 for a `0`-prefixed code.

```ts
import { digestAlgorithms } from 'node-keri';
import { blake3 } from 'some-blake3-library';

// Blake3-256 uses CESR code 'E'. Once registered, it is accepted for
// decoding, KEL verification, and generation alike.
digestAlgorithms['E'] = {
	name: 'Blake3-256',
	hash: (input) => blake3(input), // must return 32 bytes
};
```

#### Choosing an algorithm for generation

`createIdentifier`, `rotateIdentifier`, and `interactIdentifier` each accept an optional `digestCode`. It defaults to SHA-256 (`DEFAULT_DIGEST_CODE`, `'I'`); requesting a code with no registered implementation throws `UnsupportedAlgorithmError`.

```ts
import {
	createIdentifier,
	rotateIdentifier,
	generateKeyPair,
	DIGEST_CODES,
} from 'node-keri';

const nextKeyPair = generateKeyPair();
const id = createIdentifier({
	currentPrivateKey: generateKeyPair().privateKey,
	nextPublicKey: nextKeyPair.publicKey,
	digestCode: DIGEST_CODES.SHA3_256,
});
const rot = rotateIdentifier({
	state: id.state,
	currentPrivateKey: nextKeyPair.privateKey,
	nextPublicKey: generateKeyPair().publicKey,
	digestCode: DIGEST_CODES.SHA2_512, // a KEL may mix algorithms
});
```

Verification (`verifyKel`, `resolveDid`, `verifySignatureWithDid`) needs no configuration: each event's algorithm is detected from its own CESR code and recomputed under exactly that — verification is never pinned to one algorithm.

`DIGEST_CODES` names the well-known codes (`SHA2_256`, `SHA2_512`, `SHA3_256`, `SHA3_512`, `BLAKE2B_512`, `BLAKE2S_256`, `BLAKE2B_256`, `BLAKE3_256`). `decodeDigest(qb64)` decodes any recognized digest and reports its code; `encodeDigest(code, raw)` qualifies a raw digest; `digestCodeOf(qb64)` reads a digest's code; `isRegisteredDigestCode(code)` tests availability; `runDigest(code, input)` hashes through the registry.

### Errors

Programmer errors throw a subclass of `KeriError`:

| Class                       | Meaning                                                                           |
| --------------------------- | --------------------------------------------------------------------------------- |
| `InvalidArgumentError`      | An argument does not satisfy the function's contract.                             |
| `UnsupportedAlgorithmError` | A requested algorithm or derivation code is outside the supported profile.        |
| `MalformedInputError`       | Input parsed structurally but failed integrity validation (e.g. a bad CESR code). |
| `CanonicalJsonError`        | A value rejected by the canonical-JSON serialization rules.                       |

Data-level failures are _not_ thrown. `verifyKel` and `resolveDid` return a discriminated `{ ok }` result whose `error` is a `KeriVerificationError`:

```ts
type KeriVerificationError =
	| { code: 'EMPTY_KEL' }
	| { code: 'INVALID_DID'; message: string }
	| { code: 'UNSUPPORTED_FEATURE'; feature: string }
	| { code: 'INVALID_EVENT_TYPE'; eventType: string }
	| { code: 'NON_TRANSFERABLE_NOT_EXTENSIBLE'; eventType: string }
	| { code: 'DEACTIVATED_NOT_EXTENSIBLE'; eventType: string }
	| { code: 'ESTABLISHMENT_ONLY_NO_INTERACTION'; eventType: string }
	| { code: 'INVALID_SEQUENCE'; expected: number; actual: number }
	| { code: 'INVALID_PREVIOUS_DIGEST' }
	| { code: 'INVALID_EVENT_DIGEST' }
	| { code: 'INVALID_SIGNATURE' }
	| { code: 'INVALID_NEXT_KEY_COMMITMENT' }
	| { code: 'INVALID_CESR_CODE'; value: string }
	| { code: 'NON_CANONICAL_EVENT' }
	| { code: 'MALFORMED_STREAM'; message: string };
```

`verifySignatureWithDid` collapses every data-level failure to a plain `false`.

### Exported types and constants

Alongside the functions above, the package exports the full type surface:

- **Keys** — `KeriKeyPair`, `KeriPublicKey`, `KeriPrivateKey`.
- **CESR** — `CesrPublicKey`, `CesrSignature`, `CesrIndexedSignature`, `CesrDigest` (compile-time branded strings).
- **Digests** — the `digestAlgorithms` registry, the `DigestAlgorithm` type, and `runDigest` / `isRegisteredDigestCode` / `decodeDigest` / `encodeDigest` / `digestCodeOf` / `digestSpecForCode`.
- **Identifiers** — `Aid`, `DidKeri`, `ParsedDidKeri`.
- **Events** — `KeriEventType`, `KeriEventBase`, `InceptionEvent`, `NonTransferableInceptionEvent`, `RotationEvent`, `DeactivationEvent`, `InteractionEvent`, `KeriEvent`, `SignedKeriEvent` (the in-memory event shape; the wire form is a CESR stream string). `encodeEventFrame`, `parseSignedEvent`, and `parseKel` convert between the two.
- **State** — `KeriState`, the replay-derived, trusted summary of an identifier — a discriminated union of `TransferableKeriState`, `NonTransferableKeriState`, and `DeactivatedKeriState` on the `transferable` field (the two `transferable: false` members are told apart by `deactivated`).
- **DID documents** — `DidDocument`, `DidVerificationMethod`, `DidService`, `DidServiceEndpoint`, `DidResolutionResult`.
- **I/O shapes** — every `*Input` / `*Result` interface for the functions above (`CreateIdentifierInput`, `VerifyKelResult`, and so on).
- **Constants** — `KERI_PROFILE_NAME`, `SUPPORTED_KEY_ALGORITHM`, `SUPPORTED_DIGEST_ALGORITHM`, `DEFAULT_DIGEST_CODE`, `DIGEST_CODES`, `ED25519_PUBLIC_KEY_BYTES`, `ED25519_PRIVATE_SEED_BYTES`, `ED25519_SIGNATURE_BYTES`, `SHA256_DIGEST_BYTES`, `DID_KERI_PREFIX`, `KERI_VERSION_STRING_LENGTH`, `SAID_PLACEHOLDER`.

## What this library does not do

No storage, no networking, no discovery, no agent runtime, no registries, no filesystem access. It builds and verifies events; transport and persistence are the caller's responsibility.

## License

[MIT](./LICENSE)
