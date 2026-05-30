# keri

A pure, synchronous, Node.js library for the **[KERI](https://keri.one/) identity lifecycle**. Create, rotate, deactivate, sign with, and verify `did:keri` identifiers using cryptographically verifiable append-only key event logs (KEL).

Basically, KERI let's you create unique [DIDs](https://www.w3.org/TR/did-1.0/) (decentralized identifiers) which are cryptographically bound to a private key. You can rotate your keys without changing your DID, and other people can verify that the new keys are in-fact owned by the same DID owner as the previous keys. All of this is possible without any centralized service or shared blockchain. Even if your current keys are stolen or their crypto algorithm is cracked, you can rotate your keys to regain control of your identity.

> This works by storing the _next_ private key safely offline, or by storing some secret seed offline which is used to deterministically generate all future private keys for the DID

**In practice, this means you can have your own persistent "account" in decentralized, peer-to-peer networks. An obvious use-case is in agent-to-agent communication.**

This is a **deterministic state-machine library**, not an authentication framework. It has no dependencies, performs no I/O, and is entirely synchronous. The caller is responsible for secure storage and networking; the library just owns the cryptographic lifecycle. Only Ed25519 keys are supported. Not all KERI features are supported; the supported subset is the **KERI Direct JSON Profile v1** — see [PROFILE.md](./PROFILE.md) for the exact conformance boundary and [SECURITY.md](./SECURITY.md) for the trust model and security invariants.

## Installation

```
npm install node-keri
```

> Requires Node.js v20.13.x or later.

## Basic usage

### Create a new identifier

```ts
import {
	createIdentifier,
	verifyDid,
	generateKeyPair,
	publicKeyFromCesr,
} from 'node-keri';

// You can bring your own keys, or generate them like this.
const currentKeyPair = generateKeyPair();
const nextKeyPair = generateKeyPair(); // Pre-committed keys

// Mint a new did:keri identifier.
const result = createIdentifier({
	currentPrivateKey: currentKeyPair.privateKey,
	nextPublicKey: nextKeyPair.publicKey,
});

console.log(result.did); // => "did:keri:<...>"

// The KEL now contains just one event (the inception event).
const kel = result.event;

// Other people can verify the identifier via the KEL.
const verified = verifyDid({ did: result.did, kel });
if (verified.ok) {
	const publicKey = publicKeyFromCesr(verified.state.currentPublicKey);
	console.log(publicKey.export({ format: 'jwk' }));
} else {
	console.error('Verification failed!');
}
```

### Rotate an identifier's keys

```ts
import { rotateIdentifier, generateKeyPair } from 'node-keri';

currentKeyPair = nextKeyPair;
nextKeyPair = generateKeyPair(); // New pre-committed keys

const result = rotateIdentifier({
	state: verified.state,
	newPrivateKey: currentKeyPair.privateKey,
	nextPublicKey: nextKeyPair.publicKey,
});

// The KEL now contains another event (the rotation event).
kel += result.event;
```

### Sign a message

```ts
import { createSignature } from 'node-keri';

const payload = Buffer.from('a message from the DID controller');
const signature = createSignature(currentKeyPair.privateKey, payload);

console.log(signature); // CESR-qualified url-safe ASCII string
```

### Verify a signed message

```ts
import { verifySignatureWithDid } from 'node-keri';

const ok = verifySignatureWithDid({
	did,
	kel,
	payload,
	signature,
});

if (ok) {
	console.log('Verification succeeded!');
} else {
	console.log('Verification failed!');
}
```

### Key Events and the KEL

KEL stands for "Key Event Log". It is the cryptographically verifiable history of a KERI identifier. Anybody holding a KEL can independently verify it to determine the corresponding identifier's current public key. Each KEL is cryptographically bound to its corresponding identifier, so attempting to verify a KEL against the wrong identifier will always fail.

Events and KELs are exchanged as **CESR streams**, which are ASCII-safe strings. A KEL is simply a concatenation of each each event it contains, in order.

## API reference

The error policy is uniform across the whole library: **throwing is reserved for programmer errors** — a wrong argument type, a malformed key object, an unsupported KERI feature, etc. Anything that can legitimately arrive from an untrusted source — a tampered KEL, a malformed DID, a non-verifying signature — is reported as a typed `{ ok: false, error }` result or a `false` return, never thrown. Throwing functions throw a `KeriError` subclass; see [Errors](#errors).

### Identifier lifecycle

#### `createIdentifier()`

```ts
function createIdentifier(input: {
	currentPrivateKey: PrivateKey;
	nextPublicKey: PublicKey;
	establishmentOnly?: boolean;
	digestCode?: string;
}): {
	did: DidKeri;
	aid: Aid;
	event: string;
	state: KeriState;
};
```

Mint a new transferable `did:keri` identifier. You supply the key material: `currentPrivateKey` is the current signing key's private half; `nextPublicKey` is the pre-rotation key's public half. It builds and signs the inception event and returns the DID, the signed event, and the replay-derived KEL state. Keep the current private key to sign with, and securely store the next private key to rotate to later.

The returned `event` is the signed inception event in its **CESR stream** ASCII wire form. A KEL is built by concatenating these event strings in order. When an identifier is first created, its KEL is simply equal to this first event.

**Options:**

- `establishmentOnly`: set to `true` to mint an **establishment-only** identifier, which disables [interaction events](#interactonidentifier). It defaults to `false`.
- `digestCode` selects the hash algorithm for the inception SAID, AID, and next-key commitment — it defaults to `DIGEST_CODES.SHA2_256` (`I`). See [Digest algorithms](#digest-algorithms).

To mint a _non-transferable_ identifier instead — an identifier with no KEL, which can never be rotated — use [`createNonTransferableIdentifier`](#createnontransferableidentifier).

#### `rotateIdentifier()`

```ts
function rotateIdentifier(input: {
	state: KeriState;
	newPrivateKey: PrivateKey;
	nextPublicKey: PublicKey;
	digestCode?: string;
}): {
	event: string;
	state: KeriState;
};
```

Rotate an identifier's keys. `newPrivateKey` is the private half of the key being rotated _to_ (it must match with the pre-commited `nextPublicKey` of the _previous event_, or rotation will fail). `nextPublicKey` is the public half of the freshly chosen pre-rotation key for the _next_ rotation; securely store the matching private half to rotate again later. Returns the signed rotation event and the new state.

**Options:**

- `digestCode`: selects the hash for this event's SAID and new next-key commitment — it defaults to `DIGEST_CODES.SHA2_256` (`I`). See [Digest algorithms](#digest-algorithms).

#### `interactOnIdentifier()`

```ts
function interactOnIdentifier(input: {
	state: KeriState;
	currentPrivateKey: PrivateKey;
	data: readonly unknown[];
	digestCode?: string;
}): {
	event: string;
	state: KeriState;
};
```

Anchor arbitrary data to the identifier's KEL without rotating keys. `currentPrivateKey` must be the currently authoritative signing key. Each `data` entry must be plain JSON-serializable data. Returns the signed interaction event and the new state.

**Options:**

- `digestCode`: selects the hash for this event's SAID — it defaults to `DIGEST_CODES.SHA2_256` (`I`). See [Digest algorithms](#digest-algorithms).

#### `deactivateIdentifier()`

```ts
function deactivateIdentifier(input: {
	state: KeriState;
	newPrivateKey: PrivateKey;
	digestCode?: string;
}): {
	event: string;
	state: KeriState;
};
```

Permanently disables an identifier. After deactivation, the identifier cannot have any more events, it cannot be used for signing messages, and its identity is permanently considered invalid/untrustworthy. `newPrivateKey` must be the private half of the pre-commited `nextPublicKey` of the _previous event_. Returns the signed rotation event and the new state.

**Options:**

- `digestCode`: selects the hash for this event's SAID — it defaults to `DIGEST_CODES.SHA2_256` (`"I"`). See [Digest algorithms](#digest-algorithms).

#### `createNonTransferableIdentifier()`

```ts
function createNonTransferableIdentifier(input: { publicKey: PublicKey }): {
	did: DidKeri;
	aid: Aid;
	state: KeriState;
};
```

Mint a **non-transferable** `did:keri` identifier. It is self-certifying: there is no inception event and **no KEL**, and it can never rotate. Keep the matching private key to sign with.

Use the **empty string** `''` as the KEL wherever one is expected (e.g., `verifyDid({ did, kel: '' })`.

Non-transferable identifiers are useful for ephemeral, temporary identifiers.

#### `verifyIdentifier()`

```ts
function verifyIdentifier(input: {
	aid: Aid;
	kel: string;
}): { ok: true; state: KeriState } | { ok: false; error: KeriVerificationError };
```

Verify an identifier and reconstruct its latest authoritative state. **The returned `state` is the only `KeriState` a caller may treat as verified.**

A KEL that ends in a deactivation event (see [`deactivateIdentifier`](#deactivateidentifier)) verifies normally, and its `state` has `deactivated === true` and `transferable === false`.

#### `verifyDid()`

```ts
function verifyDid(input: {
	did: DidKeri;
	kel: string;
}): { ok: true; state: KeriState } | { ok: false; error: KeriVerificationError };
```

This is the DID-level counterpart of [`verifyIdentifier`](#verifyidentifier). A DID document can be subsequently created by passing the returned `state` to [`createDidDocument()`](#creatediddocument).

### Signing and verifying signatures

#### `createSignature()`

```ts
function createSignature(privateKey: PrivateKey, payload: Uint8Array): CesrSignature;
```

Sign `payload` with `privateKey` and return the signature, which is CESR-qualified url-safe ASCII string.

#### `verifySignature()`

```ts
function verifySignature(input: {
	aid: Aid;
	kel: string;
	payload: Uint8Array;
	signature: CesrSignature;
}): boolean;
```

Verifies that the provided signature is a valid signature over the provided payload, and that the signature was made by the controller of the given identifier, using the identifier's current authoritative signing key.

Returns `false` if verification fails (e.g., a non-verifying KEL, a KEL for a different identifier, a KEL for a deactivated identifier, or a malformed or mismatched signature).

#### `verifySignatureWithDid()`

```ts
function verifySignatureWithDid(input: {
	did: DidKeri;
	kel: string;
	payload: Uint8Array;
	signature: CesrSignature;
}): boolean;
```

This is the DID-level counterpart of [`verifySignature`](#verifysignature).

### DID support functions

#### `createDidDocument()`

```ts
function createDidDocument(input: {
	state: KeriState;
	services?: readonly DidService[];
}): DidDocument;
```

Project a _verified_ `KeriState` into a [W3C DID document](https://www.w3.org/TR/did-1.0/) with a single Ed25519 verification method (`JsonWebKey2020` / `publicKeyJwk`) referenced from both `authentication` and `assertionMethod`. You should only pass `state` returned by `verifyIdentifier` or `verifyDid`.

**Options:**

- `services`: populates the document's `service` field; bare-fragment ids are expanded against the document's DID.

### Key handling

This library expects `PublicKey` and `PrivateKey` inputs, which are just Node's [`KeyObject`](https://nodejs.org/api/crypto.html#class-keyobject), branded for Ed25519 and refined to their respective halves:

```ts
type PublicKey = KeyObject & { asymmetricKeyType: 'ed25519'; type: 'public' };
type PrivateKey = KeyObject & { asymmetricKeyType: 'ed25519'; type: 'private' };

interface KeyPair {
	publicKey: PublicKey;
	privateKey: PrivateKey;
}
```

#### `generateKeyPair()`

```ts
function generateKeyPair(): KeyPair;
```

Generate a fresh Ed25519 keypair from the platform [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).

#### `asPublicKey()` / `asPrivateKey()`

```ts
function asPublicKey(value: unknown): PublicKey;
function asPrivateKey(value: unknown): PrivateKey;
```

Narrow a Node `KeyObject` to a branded `PublicKey` or `PrivateKey`, throwing `InvalidArgumentError` if it is not an Ed25519 key of the correct half. Use after parsing a stored key:

```ts
import { createPrivateKey } from 'node:crypto';
import { asPrivateKey } from 'node-keri';

const privateKey = asPrivateKey(createPrivateKey(pemString)); // PEM/DER/JWK all work
```

#### `publicKeyToCesr()` / `publicKeyFromCesr()`

```ts
function publicKeyToCesr(key: PublicKey): CesrPublicKey;
function publicKeyFromCesr(cesr: CesrPublicKey): PublicKey;
```

Convert between a `PublicKey` and its CESR-qualified string form. Use `publicKeyToCesr` to compare a key you hold against a verified `KeriState`:

```ts
console.log(publicKeyToCesr(myKeyPair.publicKey) === state.currentPublicKey);
```

Use `publicKeyFromCesr` for the inverse — recover a usable `PublicKey` from `state.currentPublicKey`.

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

The registry of available digest implementations, keyed by CESR derivation code. It is populated at load with every native `node:crypto` hash the linked OpenSSL provides — SHA2-256 (`I`), SHA2-512 (`0G`), SHA3-256 (`H`), SHA3-512 (`0E`), BLAKE2s-256 (`G`), BLAKE2b-512 (`0F`).

It is **monkey-patchable**: register an algorithm `node-keri` does not ship with by assigning an entry. The implementation must return 32 bytes for a one-character code or 64 bytes for a `0`-prefixed code.

```ts
import { digestAlgorithms } from 'node-keri';
import { blake3 } from 'some-blake3-library';

// Blake3-256 uses CESR code 'E'. Once registered, node-keri can use it.
digestAlgorithms['E'] = {
	name: 'Blake3-256',
	hash: (input) => blake3(input), // must return 32 bytes
};
```

#### Choosing an algorithm for generation

`createIdentifier()`, `rotateIdentifier()`, `interactOnIdentifier()`, and `deactivateIdentifier()` each accept an optional `digestCode` option. It defaults to SHA-256 (`DIGEST_CODES.SHA2_256`, `'I'`). Attempting to use a code with no registered implementation throws `UnsupportedAlgorithmError`.

```ts
import {
	createIdentifier,
	rotateIdentifier,
	generateKeyPair,
	DIGEST_CODES,
} from 'node-keri';

const nextKeyPair = generateKeyPair();
const inception = createIdentifier({
	currentPrivateKey: generateKeyPair().privateKey,
	nextPublicKey: nextKeyPair.publicKey,
	digestCode: DIGEST_CODES.SHA3_256,
});
const rotation = rotateIdentifier({
	state: inception.state,
	newPrivateKey: nextKeyPair.privateKey,
	nextPublicKey: generateKeyPair().publicKey,
	digestCode: DIGEST_CODES.SHA2_512, // a KEL may mix digest algorithms
});
```

`DIGEST_CODES` contains the well-known codes:

- `SHA2_256`
- `SHA2_512`
- `SHA3_256`
- `SHA3_512`
- `BLAKE2B_512`
- `BLAKE2S_256`
- `BLAKE2B_256`
- `BLAKE3_256`

### Errors

Programmer errors throw a subclass of `KeriError`:

| Class                       | Meaning                                                                           |
| --------------------------- | --------------------------------------------------------------------------------- |
| `InvalidArgumentError`      | An argument does not satisfy the function's contract.                             |
| `UnsupportedAlgorithmError` | A requested algorithm or derivation code is not supported.                        |
| `MalformedInputError`       | Input parsed structurally but failed integrity validation (e.g. a bad CESR code). |
| `CanonicalJsonError`        | A value rejected by the canonical-JSON serialization rules.                       |

Data-level failures are _not_ thrown. `verifyIdentifier` and `verifyDid` return a discriminated `{ ok }` result whose `error` is a `KeriVerificationError`:

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

`verifySignature` and `verifySignatureWithDid` collapse every data-level failure to a plain `false`.

## What this library does not do

No storage, no networking, no discovery, no agent runtime, no registries, no filesystem access. It builds and verifies events; transport and persistence are the caller's responsibility.

## License

[MIT](./LICENSE)
