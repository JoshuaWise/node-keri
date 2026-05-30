# KERI Direct JSON Profile v1

This library implements a deliberately narrow subset of KERI. This document defines that subset — the **conformance boundary**. Anything outside it is rejected; the library never silently accepts an out-of-profile event.

## Scope

The profile covers a **single-controller `did:keri` identity lifecycle**: JSON events, Ed25519 keys, CESR text primitives, local KEL creation, replay verification, key rotation, interaction events, and DID document generation. Witnesses, transport, and discovery are out of scope by design — they are separable from KERI's core, which is the replay-verifiable key event log.

node-keri **generates and verifies both** transferable and non-transferable AIDs. A transferable AID is a self-certifying identifier that pre-rotates and carries a replayable KEL (`createIdentifier`). A non-transferable AID is a basic prefix whose identifier is the controller's `B`-coded Ed25519 key itself — self-certifying, with no KEL and no rotation; mint one with `createNonTransferableIdentifier` and use the empty string `''` wherever a KEL is expected. A non-transferable AID minted by another implementation (keripy, say) — which carries a trivial single-event KEL — is also ingested and verified.

## Supported

| Capability                               | Status |
| ---------------------------------------- | ------ |
| JSON KERI events                         | Yes    |
| CESR text primitives                     | Yes    |
| Ed25519 signing keys                     | Yes    |
| Self-certifying transferable AIDs        | Yes    |
| Non-transferable AIDs (basic prefix)     | Yes    |
| Single signing key (threshold 1)         | Yes    |
| Single next-key commitment               | Yes    |
| Inception (`icp`) events                 | Yes    |
| Rotation (`rot`) events                  | Yes    |
| Interaction (`ixn`) events               | Yes    |
| Deactivation (rotation to no next key)   | Yes    |
| Local KEL replay & verification          | Yes    |
| Deterministic event digesting (SAID)     | Yes    |
| Pluggable 256-/512-bit digest algorithms | Yes    |
| `did:keri` parsing & formatting          | Yes    |
| DID document generation                  | Yes    |
| Signature verification                   | Yes    |

## Excluded — and rejected

Every capability below is **outside the profile**. An event that uses one is rejected by `verifyIdentifier` with `UNSUPPORTED_FEATURE`; an out-of-profile CESR primitive is rejected with `INVALID_CESR_CODE`. The profile fails closed.

| Capability                       | Status                                                                                  |
| -------------------------------- | --------------------------------------------------------------------------------------- |
| Multisig / weighted thresholds   | Excluded                                                                                |
| Witnesses, watchers, receipts    | Excluded                                                                                |
| OOBI / discovery                 | Excluded                                                                                |
| Delegation                       | Excluded                                                                                |
| TEL / credential registries      | Excluded                                                                                |
| Configuration traits             | `EO` only — all others excluded                                                         |
| Binary CESR                      | Excluded                                                                                |
| CESR counters / groups           | Excluded except the `-A` controller-signature counter (see [Wire format](#wire-format)) |
| CBOR / MessagePack serialization | Excluded                                                                                |
| Non-Ed25519 keys                 | Excluded                                                                                |
| HTTP transport, filesystem       | Excluded                                                                                |

## Event shapes

Three event types are supported: `icp`, `rot`, `ixn`. Excluded-feature fields are pinned to fixed sentinel values, enforced both by the TypeScript types and by the replay validators:

- `kt` (signing threshold) — must be `"1"`.
- `nt` (next-key threshold) — must be `"1"`, except a non-transferable inception or a deactivation `rot` (both see below), where it is `"0"`.
- `k` — an array of **exactly one** key. Two or more is multisig.
- `n` — an array of **exactly one** next-key digest, except a non-transferable inception or a deactivation `rot`, where it is empty.
- `bt` (witness threshold) — must be `"0"`.
- `b` (witnesses), `br` / `ba` (witness cuts/adds) — must be empty arrays.
- `c` (config traits) — must be either `[]` or `["EO"]`. See [Establishment-only identifiers](#establishment-only-identifiers).
- Inception `a` (seals) — must be empty. To anchor data, use an interaction event, whose `a` is an unconstrained JSON array.
- An event carrying **any field not named by its type** is rejected.

**Non-transferable inception.** An `icp` whose `i` field is a `B`-coded Ed25519 key (rather than a self-addressing digest) is a non-transferable inception. Its `k` holds that same `B` key, `nt` is `"0"`, and `n` is empty — it commits to no next key. Its AID is the `B` key itself, so `d ≠ i` (unlike a transferable inception, where `d == i`). A non-transferable identifier's KEL is exactly this one event: any `rot` or `ixn` that follows it is rejected with `NON_TRANSFERABLE_NOT_EXTENSIBLE`, since the identifier can never rotate or extend. node-keri verifies this single-event form (e.g. from keripy) but does not emit a non-transferable inception event itself — `createNonTransferableIdentifier` mints the equivalent **no-KEL** form, where the AID stands alone with no events to replay (verify or resolve it by passing `''` as the KEL).

**Deactivation.** A `rot` whose `nt` is `"0"` and whose `n` is empty is a _deactivation_ — the `did:keri` abandonment operation, a rotation to zero forward controlling keys. It is otherwise an ordinary rotation: `k` still holds the single revealed pre-rotated key, which reproduces the prior next-key commitment and signs the event. Committing to no next key makes it terminal — it is the last event of the KEL, and any `rot` or `ixn` that follows is rejected with `DEACTIVATED_NOT_EXTENSIBLE`. The replayed `KeriState` is then `deactivated` and no longer `transferable`. node-keri both generates (`deactivateIdentifier`) and verifies deactivations.

### Establishment-only identifiers

An `icp` whose `c` field is `["EO"]` declares the _establishment-only_ configuration trait: the identifier's KEL accepts **only establishment events** (`icp`, `rot`) — interaction events are rejected. This is useful for identifiers that should never anchor application data, only roll their keys.

The trait is _inception only_: it appears in `icp` and only in `icp`, and is inherited unchanged by every later event of the KEL through the replay-derived state. Rotation, interaction, and deactivation events do not (and cannot) carry a `c` field, so the trait is set once and never changes.

Enforcement is symmetric: `createInteractionEvent` and `interactOnIdentifier` refuse a state whose `establishmentOnly` flag is set with `InvalidArgumentError`, and `verifyIdentifier` rejects an `ixn` appended out of band to such a KEL with `ESTABLISHMENT_ONLY_NO_INTERACTION`. `EO` on a non-transferable inception is redundant (the KEL is already non-extensible) and is rejected with `UNSUPPORTED_FEATURE`. Pass `establishmentOnly: true` to `createIdentifier` to mint one. The trait does not block deactivation — a deactivation is a rotation, and an EO identifier may still be abandoned.

Each signed event carries **exactly one** Ed25519 signature, attached as a CESR _indexed_ signature ("Siger") at key index 0. Zero or multiple signatures, or an index other than 0, are rejected. See [Wire format](#wire-format).

## Canonical JSON

Events are serialized for digesting and signing with a single deterministic canonicalization:

- Object keys emitted in the object's own property (insertion) order, never sorted.
- No insignificant whitespace.
- UTF-8 byte output.
- Array order preserved.
- `NaN`, `Infinity`, `-0`, `undefined`, functions, and symbols are rejected.

Event top-level fields follow KERI's fixed, type-specific **canonical field order** — not alphabetical order. Every event is reordered into that canonical order (`toCanonicalEvent`) before serialization, so the digested and signed bytes never depend on the order in which the event object was constructed in code or parsed from JSON:

| Event | Canonical field order              |
| ----- | ---------------------------------- |
| `icp` | `v t d i s kt k nt n bt b c a`     |
| `rot` | `v t d i s p kt k nt n bt br ba a` |
| `ixn` | `v t d i s p a`                    |

The event digest (`d`) is a self-addressing identifier (SAID) computed over the canonical event with the digest field(s) replaced by a fixed-length placeholder. For a transferable inception the AID _is_ the SAID — `d` and `i` are identical, and both are placeholdered while the SAID is computed. For a non-transferable inception `i` is the controller's key, a fixed input to the digest, so only `d` is placeholdered and `d ≠ i`. The hash algorithm is whatever the digest's own CESR code names — see [Digest algorithms](#digest-algorithms) — so different events in one KEL may use different algorithms; SHA-256 is the default for events this library generates.

## CESR subset

Qualified text primitives — keys and signatures are Ed25519-only; digests are algorithm-agile:

| Primitive                            | Code         | Qualified length |
| ------------------------------------ | ------------ | ---------------- |
| Ed25519 public key, transferable     | `D`          | 44 chars         |
| Ed25519 public key, non-transferable | `B`          | 44 chars         |
| Ed25519 signature                    | `0B`         | 88 chars         |
| Ed25519 indexed signature            | `A`          | 88 chars         |
| 256-bit digest                       | one char     | 44 chars         |
| 512-bit digest                       | `0`-prefixed | 88 chars         |

The non-transferable key code (`B`) is the AID and `currentPublicKey` of a non-transferable identifier — minted by `createNonTransferableIdentifier`, which encodes it with `encodeNonTransferablePublicKeyEd25519` — and the `i`/`k` of a non-transferable inception event ingested from another implementation. node-keri both encodes and decodes it.

The non-indexed signature (`0B`, a "Cigar") is used for detached signatures over arbitrary payloads. The indexed signature (`A`, a "Siger") carries the index of the signing key within the establishment event's key list, encoded in a 1-character "soft" field after the code — it is the form attached to events in the wire stream. In this single-key profile that index is always 0.

Decoders enforce the derivation code, the fixed length, the base64url alphabet, and **pad-bit canonicality** (the leading pad bits must be zero, so no malleable alternate encoding decodes to the same bytes). Unknown codes, wrong lengths, and non-canonical encodings are rejected.

A digest code is accepted only when an implementation is registered for it (see [Digest algorithms](#digest-algorithms)); a digest under an unregistered code is rejected with `INVALID_CESR_CODE`.

## Wire format

An event and its signature(s) are exchanged as a **CESR stream frame**, not as a JSON wrapper object:

```text
<event canonical JSON><-A counter><indexed signature ...>
```

- The event's canonical JSON comes first. Its version string `v` declares the event's exact byte length, so a reader always knows where the JSON ends.
- The attachment group follows immediately: a `-A` "ControllerIdxSigs" counter (the code `-A` plus a 2-character base64 count) and then that many indexed signatures (`A`, 88 chars each).
- A KEL is the frames of its events **concatenated in order**, with no separators or envelope.

The profile accepts exactly one counter — `-A` — and exactly one signature under it. Any other counter (witness signatures, receipt couples, CESR version/genus groups) names an excluded feature and is rejected; a stream that is not well-framed is rejected with `MALFORMED_STREAM`. Binary CESR is not accepted — the stream is text (base64 / UTF-8 JSON) only.

`SignedKeriEvent` is the in-memory shape of one event; the stream is its serialization. The library converts between them with `encodeEventFrame` / `parseSignedEvent` / `parseKel`, and every high-level function takes or returns the stream form.

## Digest algorithms

KERI digests are self-describing: a qualified digest's CESR code names its hash algorithm, so a KEL may freely mix algorithms across events. This library follows that — the policy is **"any available 256-bit or 512-bit hash"**:

- A one-character code denotes a 256-bit (32-byte) digest; a `0`-prefixed two-character code a 512-bit (64-byte) one. No other digest widths are supported.
- node-keri auto-registers every native `node:crypto` hash the linked OpenSSL provides — SHA2-256/512, SHA3-256/512, BLAKE2s-256, BLAKE2b-512. SHA3 and BLAKE2 availability is build-dependent, so the runtime registry is the source of truth.
- The `digestAlgorithms` registry maps CESR code → implementation and is monkey-patchable: a caller can register an algorithm node-keri does not ship (e.g. Blake3-256) and it is then accepted for decoding, verification, and generation alike.
- **Generation** defaults to SHA-256 (`I`); pass a `digestCode` to `createIdentifier` / `rotateIdentifier` / `interactOnIdentifier` to pick another. **Verification** auto-detects each digest's algorithm from its code and recomputes under exactly that — it is never pinned to one algorithm.
- The library fails closed: a digest under a code with no registered implementation is rejected, never assumed.

## `did:keri` method

- DID syntax: `did:keri:<aid>`, where `<aid>` is either a transferable AID — the inception event's SAID, a CESR-qualified digest under any registered algorithm (44 chars for a 256-bit digest, 88 for a 512-bit one) — or a non-transferable AID, a CESR-qualified `B`-coded Ed25519 key (44 chars).
- The parser is strict and offline: DID-URL components (path, query, fragment) are rejected, and the identifier must be a well-formed AID of either kind.
- Resolution is local only — the caller supplies the KEL. The library never discovers, fetches, or persists anything.
- A DID document is a projection of one **verified** key state: it advertises the single currently-authoritative Ed25519 key as a `JsonWebKey2020` verification method, referenced from `authentication` and `assertionMethod`.
- A non-transferable DID is self-certifying: its key _is_ the AID. The verifiers therefore need no KEL for one — `kel` is a required parameter, but the **empty string** `''` is the "no KEL" value, and for a non-transferable identifier the key (and hence the state, or a DID document projected from it) is then derived straight from the prefix. This holds uniformly at both layers: the AID-level `verifyIdentifier` / `verifySignature` and their DID-level counterparts `verifyDid` / `verifySignatureWithDid` all accept the empty-string "no KEL" value for a non-transferable identifier. A non-transferable identifier may equally be verified from its trivial single-event KEL by passing that stream instead.

## Conformance notes

This profile is intentionally not wire-compatible with every KERI implementation. It targets internal consistency and replay-verifiability for the single-controller identity use case. Where this canonicalization or CESR table diverges from another KERI deployment, digests diverge and cross-verification will not hold — that boundary is explicit and by design.
