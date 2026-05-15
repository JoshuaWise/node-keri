# KERI Direct JSON Profile v1

This library implements a deliberately narrow subset of KERI. This document defines that subset — the **conformance boundary**. Anything outside it is rejected; the library never silently accepts an out-of-profile event.

## Scope

The profile covers a **single-controller, transferable `did:keri` identity lifecycle**: JSON events, Ed25519 keys, CESR text primitives, local KEL creation, replay verification, key rotation, interaction events, and DID document generation. Witnesses, transport, and discovery are out of scope by design — they are separable from KERI's core, which is the replay-verifiable key event log.

## Supported

| Capability                           | Status |
| ------------------------------------ | ------ |
| JSON KERI events                     | Yes    |
| CESR text primitives                 | Yes    |
| Ed25519 signing keys                 | Yes    |
| Self-certifying transferable AIDs    | Yes    |
| Single signing key (threshold 1)     | Yes    |
| Single next-key commitment           | Yes    |
| Inception (`icp`) events             | Yes    |
| Rotation (`rot`) events              | Yes    |
| Interaction (`ixn`) events           | Yes    |
| Local KEL replay & verification      | Yes    |
| Deterministic event digesting (SAID) | Yes    |
| `did:keri` parsing & formatting      | Yes    |
| DID document generation              | Yes    |
| Signature verification               | Yes    |

## Excluded — and rejected

Every capability below is **outside the profile**. An event that uses one is rejected by `verifyKel` with `UNSUPPORTED_FEATURE`; an out-of-profile CESR primitive is rejected with `INVALID_CESR_CODE`. The profile fails closed.

| Capability                       | Status   |
| -------------------------------- | -------- |
| Multisig / weighted thresholds   | Excluded |
| Witnesses, watchers, receipts    | Excluded |
| OOBI / discovery                 | Excluded |
| Delegation                       | Excluded |
| TEL / credential registries      | Excluded |
| Configuration traits             | Excluded |
| Binary CESR, counters, groups    | Excluded |
| CBOR / MessagePack serialization | Excluded |
| Non-Ed25519 keys                 | Excluded |
| Non-SHA-256 digests              | Excluded |
| HTTP transport, filesystem       | Excluded |

## Event shapes

Three event types are supported: `icp`, `rot`, `ixn`. Excluded-feature fields are pinned to fixed sentinel values, enforced both by the TypeScript types and by the replay validators:

- `kt` (signing threshold) — must be `"1"`.
- `nt` (next-key threshold) — must be `"1"`.
- `k` / `n` — arrays of **exactly one** entry. Two or more is multisig.
- `bt` (witness threshold) — must be `"0"`.
- `b` (witnesses), `c` (config traits), `br` / `ba` (witness cuts/adds) — must be empty arrays.
- Inception `a` (seals) — must be empty. To anchor data, use an interaction event, whose `a` is an unconstrained JSON array.
- An event carrying **any field not named by its type** is rejected.

Each signed event carries **exactly one** Ed25519 signature. Zero or multiple signatures are rejected.

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

The event digest (`d`) is a SHA-256 self-addressing identifier (SAID) computed over the canonical event with the digest field(s) replaced by a fixed-length placeholder. For inception, the AID _is_ the SAID — `d` and `i` are identical.

## CESR subset

Only three qualified text primitives are implemented:

| Primitive          | Code | Qualified length |
| ------------------ | ---- | ---------------- |
| Ed25519 public key | `D`  | 44 chars         |
| Ed25519 signature  | `0B` | 88 chars         |
| SHA-256 digest     | `I`  | 44 chars         |

Decoders enforce the derivation code, the fixed length, the base64url alphabet, and **pad-bit canonicality** (the leading pad bits must be zero, so no malleable alternate encoding decodes to the same bytes). Unknown codes, wrong lengths, and non-canonical encodings are rejected.

## `did:keri` method

- DID syntax: `did:keri:<aid>`, where `<aid>` is a CESR-qualified SHA-256 digest (the inception event's SAID).
- The parser is strict and offline: DID-URL components (path, query, fragment) are rejected, and the identifier must be a well-formed AID.
- Resolution is local only — the caller supplies the KEL. The library never discovers, fetches, or persists anything.
- A DID document is a projection of one **verified** key state: it advertises the single currently-authoritative Ed25519 key as a `JsonWebKey2020` verification method, referenced from `authentication` and `assertionMethod`.

## Conformance notes

This profile is intentionally not wire-compatible with every KERI implementation. It targets internal consistency and replay-verifiability for the single-controller identity use case. Where this canonicalization or CESR table diverges from another KERI deployment, digests diverge and cross-verification will not hold — that boundary is explicit and by design.
