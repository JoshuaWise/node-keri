/**
 * KEL replay verifier — the core of Milestone 4.
 *
 * `replayKel` walks a key event log from inception to the latest event and
 * reconstructs the authoritative `KeriState` from scratch. Nothing about the
 * input is trusted: every event's structure, self-addressing digest, version
 * string, sequence number, previous-event link, rotation commitment, and
 * signature is recomputed and checked against the state derived purely from
 * earlier events. The returned state is the *only* state in the library a
 * caller may treat as verified.
 *
 * Verification failures are returned as discriminated `KeriVerificationError`
 * result objects, never thrown — a malformed or hostile KEL is expected input,
 * not a programmer error.
 *
 * Per-event check order is deliberate. The self-addressing digest is checked
 * before the sequence number so that an *authentic* event placed at the wrong
 * index (a reordering attack) passes the digest check and is then caught by
 * the sequence/previous-digest checks with an accurate diagnosis, while a
 * *tampered* event fails the digest check directly.
 */

import { digestCodeOf } from '../cesr/codes';
import { decodePublicKeyEd25519 } from '../cesr/decode';
import { CesrDigest, CesrIndexedSignature, CesrPublicKey } from '../cesr/qualified';
import { publicKeyFromRaw } from '../crypto/keypair';
import { canonicalizeJson } from '../event/canonical-json';
import {
	computeEventSaid,
	deriveNextKeyCommitment,
	saidPlaceholder,
} from '../event/digest';
import { toCanonicalEvent } from '../event/field-order';
import { parseStreamResult } from '../event/stream';
import { verifyEventSignature } from '../event/verify-signature';
import { Aid, formatDidKeri } from '../did/did-keri';
import {
	CanonicalJsonError,
	KeriVerificationError,
	MalformedInputError,
	UnsupportedAlgorithmError,
} from '../profile/errors';
import { KeriState, TransferableKeriState } from './state';
import { describe, isRecord, checkSignature } from './shape';
import { validateInceptionShape } from './validate-inception';
import { validateInteractionShape } from './validate-interaction';
import { validateRotationShape } from './validate-rotation';

/** Discriminated result of verifying an entire KEL. */
export type VerifyIdentifierResult =
	| { ok: true; state: KeriState }
	| { ok: false; error: KeriVerificationError };

/** Internal per-event outcome: a fresh state, or the error that stopped us. */
type StepResult =
	| { ok: true; state: KeriState }
	| { ok: false; error: KeriVerificationError };

/**
 * Build a failure result. Typed as the bare `{ ok: false }` arm — which is
 * common to both `StepResult` and `VerifyIdentifierResult` — so `replayKel` and the
 * per-event `apply*` helpers can all `return fail(...)` directly.
 */
function fail(error: KeriVerificationError): { ok: false; error: KeriVerificationError } {
	return { ok: false, error };
}

/** Variable-time byte equality. Use for non-secret comparisons only. */
function bytesEqual(a: Readonly<Uint8Array>, b: Readonly<Uint8Array>): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

/**
 * Confirm an event's on-wire JSON bytes are exactly its canonical
 * serialization — KERI's fixed, type-specific field order with no
 * insignificant whitespace.
 *
 * The replay verifier recomputes every digest and signature over the event
 * *re-canonicalized* through `toCanonicalEvent`, so an event whose wire bytes
 * differ only in field order would otherwise verify here even though a strict
 * KERI verifier — one that digests the bytes as received — would reject it.
 * Comparing the raw frame bytes against the canonical form closes that gap, so
 * a non-canonical KEL fails closed with `NON_CANONICAL_EVENT` instead of being
 * silently normalized.
 *
 * Called only after shape validation, so `event.t` is a known event type and
 * `toCanonicalEvent` cannot throw; a `canonicalizeJson` failure (a non-JSON-
 * safe interaction anchor) is reported with the same code, consistent with how
 * such an anchor surfaces from SAID recomputation.
 */
function checkCanonicalBytes(
	event: Record<string, unknown>,
	eventBytes: Readonly<Uint8Array>
): boolean {
	let canonicalBytes: Uint8Array;
	try {
		canonicalBytes = canonicalizeJson(toCanonicalEvent(event));
	} catch {
		return false;
	}
	return bytesEqual(canonicalBytes, eventBytes);
}

/**
 * Replay the CESR stream `kel` and verify it forms a valid KEL for `aid`.
 *
 * `kel` is the wire form — event frames concatenated. It is first parsed into
 * signed events; a framing defect is reported as `MALFORMED_STREAM` before any
 * semantic check runs. `aid` is the identifier the caller expects this KEL to
 * belong to; the inception event must derive exactly that AID, otherwise the
 * KEL — however internally consistent — is for a different identifier.
 */
export function replayKel(aid: string, kel: string): VerifyIdentifierResult {
	const parsed = parseStreamResult(kel);
	if (!parsed.ok) {
		return fail({ code: 'MALFORMED_STREAM', message: parsed.message });
	}
	const frames = parsed.frames;
	if (frames.length === 0) {
		return fail({ code: 'EMPTY_KEL' });
	}

	let state: KeriState | undefined;

	for (let index = 0; index < frames.length; index++) {
		const frame = frames[index]!;
		const wrapper = readWrapper(frame.signed);
		if (!wrapper.ok) return wrapper;
		const { event, signature } = wrapper.value;
		const t = event.t;

		let step: StepResult;
		if (index === 0) {
			if (t !== 'icp') {
				return fail({
					code: 'INVALID_EVENT_TYPE',
					eventType: typeof t === 'string' ? t : describe(t),
				});
			}
			step = applyInception(aid, event, frame.eventBytes, signature);
		} else {
			// `state` is always defined here: index 0 either set it or returned.
			const prior = state as KeriState;
			// A non-transferable identifier's KEL ends at inception, and a
			// deactivated one ends at its deactivation event: neither commits
			// to a next key, so neither can rotate or anchor interactions. Any
			// further event is rejected before its shape is even examined.
			if (!prior.transferable) {
				return fail({
					code: prior.deactivated
						? 'DEACTIVATED_NOT_EXTENSIBLE'
						: 'NON_TRANSFERABLE_NOT_EXTENSIBLE',
					eventType: typeof t === 'string' ? t : describe(t),
				});
			}
			if (t === 'rot') {
				step = applyRotation(prior, event, frame.eventBytes, signature);
			} else if (t === 'ixn') {
				// An establishment-only identifier accepts no interaction
				// events. The trait was declared at inception and carried
				// forward on every state since; reject before validating
				// shape, the same way we reject events on a closed KEL.
				if (prior.establishmentOnly) {
					return fail({
						code: 'ESTABLISHMENT_ONLY_NO_INTERACTION',
						eventType: 'ixn',
					});
				}
				step = applyInteraction(prior, event, frame.eventBytes, signature);
			} else {
				// A second `icp`, or an unknown type, both land here.
				return fail({
					code: 'INVALID_EVENT_TYPE',
					eventType: typeof t === 'string' ? t : describe(t),
				});
			}
		}

		if (!step.ok) return step;
		state = step.state;
	}

	return { ok: true, state: state as KeriState };
}

/** Unwrap a SignedKeriEvent: confirm the event object and single signature. */
function readWrapper(signed: unknown):
	| {
			ok: true;
			value: { event: Record<string, unknown>; signature: CesrIndexedSignature };
	  }
	| { ok: false; error: KeriVerificationError } {
	if (!isRecord(signed)) {
		return {
			ok: false,
			error: { code: 'INVALID_EVENT_TYPE', eventType: describe(signed) },
		};
	}
	const event = signed.event;
	if (!isRecord(event)) {
		return {
			ok: false,
			error: { code: 'INVALID_EVENT_TYPE', eventType: describe(event) },
		};
	}
	const signatures = signed.signatures;
	if (!Array.isArray(signatures) || signatures.length !== 1) {
		return {
			ok: false,
			error: {
				code: 'UNSUPPORTED_FEATURE',
				feature: `exactly one signature required, got ${
					Array.isArray(signatures) ? signatures.length : describe(signatures)
				}`,
			},
		};
	}
	const sigError = checkSignature(signatures[0]);
	if (sigError) return { ok: false, error: sigError };
	return {
		ok: true,
		value: { event, signature: signatures[0] as CesrIndexedSignature },
	};
}

/**
 * Verify an inception event and build the initial state.
 *
 * Handles both AID kinds. The shape pass classifies the event from its `i`
 * field; the difference here is in two places — how the SAID is recomputed
 * (`i` is part of the digest input for a non-transferable AID, but a
 * placeholder for a transferable one, whose AID *is* the SAID) and how the AID
 * is then derived and checked.
 */
function applyInception(
	aid: string,
	event: Record<string, unknown>,
	eventBytes: Readonly<Uint8Array>,
	signature: CesrIndexedSignature
): StepResult {
	const shape = validateInceptionShape(event);
	if (!shape.ok) return shape;
	const canonical = checkCanonicalBytes(event, eventBytes);
	if (!canonical) return fail({ code: 'NON_CANONICAL_EVENT' });
	const validated = shape.value;
	const ie = validated.event;

	// The digest algorithm is read from the event's own `d` code — the shape
	// pass already confirmed it is a recognized, available digest — and the
	// SAID is recomputed under exactly that algorithm.
	let said: CesrDigest;
	let versionString: string;
	try {
		const digestCode = digestCodeOf(ie.d);
		const placeholder = saidPlaceholder(digestCode);
		// `d` is always self-addressing. `i` is self-addressing only for a
		// transferable AID, where the AID *is* the SAID; for a non-transferable
		// AID `i` is the controller's key — a fixed input to the digest, kept
		// verbatim.
		const computed = computeEventSaid(
			{
				t: 'icp',
				d: placeholder,
				i: validated.transferable ? placeholder : ie.i,
				s: ie.s,
				kt: ie.kt,
				k: ie.k,
				nt: ie.nt,
				n: ie.n,
				bt: ie.bt,
				b: ie.b,
				c: ie.c,
				a: ie.a,
			},
			digestCode
		);
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		if (
			err instanceof UnsupportedAlgorithmError
			|| err instanceof MalformedInputError
		) {
			return fail({ code: 'INVALID_CESR_CODE', value: ie.d });
		}
		throw err;
	}

	// Digest before version: a tampered content field is diagnosed as a
	// digest mismatch, while an authentic event with only a mis-declared
	// size falls through to the version check below.
	if (ie.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (ie.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });

	if (validated.transferable) {
		// The AID is the event's self-addressing digest, recorded in `i`.
		if ((ie.i as string) !== (said as string)) {
			return fail({
				code: 'INVALID_DID',
				message: 'inception `i` is not its own self-addressing digest',
			});
		}
		if (said !== aid) {
			return fail({
				code: 'INVALID_DID',
				message: 'inception event does not derive the requested AID',
			});
		}
	} else {
		// The AID is a basic prefix: the controller's own signing key, so it
		// must equal both `i` and the single entry of `k`.
		if ((ie.i as string) !== (ie.k[0] as string)) {
			return fail({
				code: 'INVALID_DID',
				message: 'non-transferable `i` is not the controller signing key',
			});
		}
		if (ie.i !== aid) {
			return fail({
				code: 'INVALID_DID',
				message: 'inception event does not derive the requested AID',
			});
		}
	}

	// Inception is sequence 0 by definition; the shape pass already confirmed
	// `s` is canonical hex, so this comparison only rejects a non-zero value.
	const seq = Number.parseInt(ie.s, 16);
	if (seq !== 0) {
		return fail({ code: 'INVALID_SEQUENCE', expected: 0, actual: seq });
	}

	if (!verifyEventSignature(ie, ie.k[0], signature)) {
		return fail({ code: 'INVALID_SIGNATURE' });
	}

	const base = {
		aid: aid as Aid,
		did: formatDidKeri(aid as Aid),
		lastSequenceNumber: 0,
		lastEventType: 'icp' as const,
		lastEventDigest: said,
		currentPublicKey: ie.k[0],
	};
	if (validated.transferable) {
		const state: TransferableKeriState = {
			...base,
			nextKeyCommitment: validated.event.n[0],
			transferable: true,
			deactivated: false,
			establishmentOnly: validated.establishmentOnly,
		};
		return { ok: true, state };
	}
	// A non-transferable identifier carries no next-key commitment.
	return { ok: true, state: { ...base, transferable: false, deactivated: false } };
}

/**
 * Verify a `rot` event against `state` and produce the next state — an
 * ordinary rotation yields a rotated `TransferableKeriState`, while a
 * deactivation (empty `nt`/`n`) yields a terminal `DeactivatedKeriState` that
 * the replay loop will refuse to extend.
 */
function applyRotation(
	state: TransferableKeriState,
	event: Record<string, unknown>,
	eventBytes: Readonly<Uint8Array>,
	signature: CesrIndexedSignature
): StepResult {
	const shape = validateRotationShape(event);
	if (!shape.ok) return shape;
	const canonical = checkCanonicalBytes(event, eventBytes);
	if (!canonical) return fail({ code: 'NON_CANONICAL_EVENT' });
	const validated = shape.value;
	const re = validated.event;

	let said: CesrDigest;
	let versionString: string;
	try {
		const digestCode = digestCodeOf(re.d);
		const computed = computeEventSaid(
			{
				t: 'rot',
				d: saidPlaceholder(digestCode),
				i: re.i,
				s: re.s,
				p: re.p,
				kt: re.kt,
				k: re.k,
				nt: re.nt,
				n: re.n,
				bt: re.bt,
				br: re.br,
				ba: re.ba,
				a: re.a,
			},
			digestCode
		);
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		if (
			err instanceof UnsupportedAlgorithmError
			|| err instanceof MalformedInputError
		) {
			return fail({ code: 'INVALID_CESR_CODE', value: re.d });
		}
		throw err;
	}

	if (re.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (re.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });
	if (re.i !== state.aid) {
		return fail({
			code: 'INVALID_DID',
			message: 'rotation event `i` does not match the KEL AID',
		});
	}

	const expectedSeq = state.lastSequenceNumber + 1;
	const seq = Number.parseInt(re.s, 16);
	if (!Number.isSafeInteger(seq) || seq !== expectedSeq) {
		return fail({ code: 'INVALID_SEQUENCE', expected: expectedSeq, actual: seq });
	}
	if (re.p !== state.lastEventDigest) {
		return fail({ code: 'INVALID_PREVIOUS_DIGEST' });
	}

	// Pre-rotation: the disclosed signing key, hashed exactly as the prior
	// event committed it, must reproduce that next-key commitment. The prior
	// commitment names its own algorithm in its CESR code, so the recomputation
	// uses that — not this event's digest code, which may differ.
	let revealedCommitment: CesrDigest;
	try {
		const priorCommitmentCode = digestCodeOf(state.nextKeyCommitment);
		revealedCommitment = deriveNextKeyCommitment(
			publicKeyFromRaw(decodePublicKeyEd25519(re.k[0])),
			priorCommitmentCode
		);
	} catch (err) {
		if (
			err instanceof UnsupportedAlgorithmError
			|| err instanceof MalformedInputError
		) {
			return fail({ code: 'INVALID_NEXT_KEY_COMMITMENT' });
		}
		throw err;
	}
	if (revealedCommitment !== state.nextKeyCommitment) {
		return fail({ code: 'INVALID_NEXT_KEY_COMMITMENT' });
	}

	// A rotation is authorized by the key it reveals, not the outgoing key.
	// This holds for a deactivation too: it still reveals the pre-rotated key.
	if (!verifyEventSignature(re, re.k[0], signature)) {
		return fail({ code: 'INVALID_SIGNATURE' });
	}

	if (validated.deactivation) {
		// A deactivation commits to no next key: the identifier is abandoned
		// and the KEL ends here. The state carries no `nextKeyCommitment`.
		return {
			ok: true,
			state: {
				aid: state.aid,
				did: state.did,
				lastSequenceNumber: seq,
				lastEventType: 'rot',
				lastEventDigest: said,
				transferable: false,
				deactivated: true,
				// The `EO` trait is set at inception and inherited unchanged thereafter —
				// neither a rotation nor a deactivation can introduce or remove it.
				establishmentOnly: state.establishmentOnly,
			},
		};
	}

	return {
		ok: true,
		state: {
			aid: state.aid,
			did: state.did,
			lastSequenceNumber: seq,
			lastEventType: 'rot',
			lastEventDigest: said,
			currentPublicKey: re.k[0],
			nextKeyCommitment: validated.event.n[0],
			transferable: true,
			deactivated: false,
			// The `EO` trait is set at inception and inherited unchanged thereafter —
			// neither a rotation nor a deactivation can introduce or remove it.
			establishmentOnly: state.establishmentOnly,
		},
	};
}

/** Verify an interaction event against `state`; key material is unchanged. */
function applyInteraction(
	state: TransferableKeriState,
	event: Record<string, unknown>,
	eventBytes: Readonly<Uint8Array>,
	signature: CesrIndexedSignature
): StepResult {
	const shape = validateInteractionShape(event);
	if (!shape.ok) return shape;
	const canonical = checkCanonicalBytes(event, eventBytes);
	if (!canonical) return fail({ code: 'NON_CANONICAL_EVENT' });
	const xe = shape.value;

	let said: CesrDigest;
	let versionString: string;
	try {
		const digestCode = digestCodeOf(xe.d);
		const computed = computeEventSaid(
			{
				t: 'ixn',
				d: saidPlaceholder(digestCode),
				i: xe.i,
				s: xe.s,
				p: xe.p,
				a: xe.a,
			},
			digestCode
		);
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			// A non-JSON-safe anchor in `a` surfaces here.
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		if (
			err instanceof UnsupportedAlgorithmError
			|| err instanceof MalformedInputError
		) {
			return fail({ code: 'INVALID_CESR_CODE', value: xe.d });
		}
		throw err;
	}

	if (xe.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (xe.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });
	if (xe.i !== state.aid) {
		return fail({
			code: 'INVALID_DID',
			message: 'interaction event `i` does not match the KEL AID',
		});
	}

	const expectedSeq = state.lastSequenceNumber + 1;
	const seq = Number.parseInt(xe.s, 16);
	if (!Number.isSafeInteger(seq) || seq !== expectedSeq) {
		return fail({ code: 'INVALID_SEQUENCE', expected: expectedSeq, actual: seq });
	}
	if (xe.p !== state.lastEventDigest) {
		return fail({ code: 'INVALID_PREVIOUS_DIGEST' });
	}

	// An interaction is signed by whatever key is currently authoritative.
	if (!verifyEventSignature(xe, state.currentPublicKey as CesrPublicKey, signature)) {
		return fail({ code: 'INVALID_SIGNATURE' });
	}

	return {
		ok: true,
		state: {
			aid: state.aid,
			did: state.did,
			lastSequenceNumber: seq,
			lastEventType: 'ixn',
			lastEventDigest: said,
			currentPublicKey: state.currentPublicKey,
			nextKeyCommitment: state.nextKeyCommitment,
			transferable: true,
			deactivated: false,
			establishmentOnly: false,
		},
	};
}
