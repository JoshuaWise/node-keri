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

import { decodePublicKeyEd25519 } from '../cesr/decode';
import { CesrDigest, CesrPublicKey, CesrSignature } from '../cesr/qualified';
import { publicKeyFromRaw } from '../crypto/keypair';
import {
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
} from '../event/digest';
import { SignedKeriEvent } from '../event/types';
import { verifyEventSignature } from '../event/verify-signature';
import { Aid, formatDidKeri } from '../did/did-keri';
import { CanonicalJsonError, KeriVerificationError } from '../profile/errors';
import { KeriState } from './state';
import { describe, isRecord, checkSignature } from './shape';
import { validateInceptionShape } from './validate-inception';
import { validateInteractionShape } from './validate-interaction';
import { validateRotationShape } from './validate-rotation';

/** Discriminated result of verifying an entire KEL. */
export type VerifyKelResult =
	| { ok: true; state: KeriState }
	| { ok: false; error: KeriVerificationError };

/** Internal per-event outcome: a fresh state, or the error that stopped us. */
type StepResult =
	| { ok: true; state: KeriState }
	| { ok: false; error: KeriVerificationError };

function fail(error: KeriVerificationError): StepResult {
	return { ok: false, error };
}

/**
 * Replay `events` and verify they form a valid KEL for `aid`.
 *
 * `aid` is the identifier the caller expects this KEL to belong to; the
 * inception event must derive exactly that AID, otherwise the KEL — however
 * internally consistent — is for a different identifier.
 */
export function replayKel(aid: Aid, events: readonly SignedKeriEvent[]): VerifyKelResult {
	if (events.length === 0) {
		return fail({ code: 'EMPTY_KEL' });
	}

	let state: KeriState | undefined;

	for (let index = 0; index < events.length; index++) {
		const wrapper = readWrapper(events[index]);
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
			step = applyInception(aid, event, signature);
		} else {
			// `state` is always defined here: index 0 either set it or returned.
			if (t === 'rot') {
				step = applyRotation(state as KeriState, event, signature);
			} else if (t === 'ixn') {
				step = applyInteraction(state as KeriState, event, signature);
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
			value: { event: Record<string, unknown>; signature: CesrSignature };
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
		value: { event, signature: signatures[0] as CesrSignature },
	};
}

/** Verify an inception event and build the initial state. */
function applyInception(
	aid: Aid,
	event: Record<string, unknown>,
	signature: CesrSignature
): StepResult {
	const shape = validateInceptionShape(event);
	if (!shape.ok) return shape;
	const ie = shape.value;

	let said: CesrDigest;
	let versionString: string;
	try {
		const computed = computeEventSaid({
			t: 'icp',
			d: SAID_PLACEHOLDER,
			i: SAID_PLACEHOLDER,
			s: ie.s,
			kt: ie.kt,
			k: ie.k,
			nt: ie.nt,
			n: ie.n,
			bt: ie.bt,
			b: ie.b,
			c: ie.c,
			a: ie.a,
		});
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		throw err;
	}

	// Digest before version: a tampered content field is diagnosed as a
	// digest mismatch, while an authentic event with only a mis-declared
	// size falls through to the version check below.
	if (ie.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (ie.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });
	if ((ie.i as string) !== (said as string)) {
		return fail({
			code: 'INVALID_DID',
			message: 'inception `i` is not its own self-addressing digest',
		});
	}
	if ((said as string) !== (aid as string)) {
		return fail({
			code: 'INVALID_DID',
			message: 'inception event does not derive the requested AID',
		});
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

	return {
		ok: true,
		state: {
			aid,
			did: formatDidKeri(aid),
			sequenceNumber: 0,
			lastEventDigest: said,
			currentPublicKey: ie.k[0],
			nextKeyCommitment: ie.n[0],
			transferable: true,
			eventType: 'icp',
		},
	};
}

/** Verify a rotation event against `state` and produce the rotated state. */
function applyRotation(
	state: KeriState,
	event: Record<string, unknown>,
	signature: CesrSignature
): StepResult {
	const shape = validateRotationShape(event);
	if (!shape.ok) return shape;
	const re = shape.value;

	let said: CesrDigest;
	let versionString: string;
	try {
		const computed = computeEventSaid({
			t: 'rot',
			d: SAID_PLACEHOLDER,
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
		});
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		throw err;
	}

	if (re.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (re.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });
	if ((re.i as string) !== (state.aid as string)) {
		return fail({
			code: 'INVALID_DID',
			message: 'rotation event `i` does not match the KEL AID',
		});
	}

	const expectedSeq = state.sequenceNumber + 1;
	const seq = Number.parseInt(re.s, 16);
	if (!Number.isSafeInteger(seq) || seq !== expectedSeq) {
		return fail({ code: 'INVALID_SEQUENCE', expected: expectedSeq, actual: seq });
	}
	if ((re.p as string) !== (state.lastEventDigest as string)) {
		return fail({ code: 'INVALID_PREVIOUS_DIGEST' });
	}

	// Pre-rotation: the disclosed signing key, hashed exactly as the prior
	// event committed it, must reproduce that next-key commitment.
	const revealedCommitment = deriveNextKeyCommitment(
		publicKeyFromRaw(decodePublicKeyEd25519(re.k[0]))
	);
	if ((revealedCommitment as string) !== (state.nextKeyCommitment as string)) {
		return fail({ code: 'INVALID_NEXT_KEY_COMMITMENT' });
	}

	// A rotation is authorized by the key it reveals, not the outgoing key.
	if (!verifyEventSignature(re, re.k[0], signature)) {
		return fail({ code: 'INVALID_SIGNATURE' });
	}

	return {
		ok: true,
		state: {
			aid: state.aid,
			did: state.did,
			sequenceNumber: seq,
			lastEventDigest: said,
			currentPublicKey: re.k[0],
			nextKeyCommitment: re.n[0],
			transferable: true,
			eventType: 'rot',
		},
	};
}

/** Verify an interaction event against `state`; key material is unchanged. */
function applyInteraction(
	state: KeriState,
	event: Record<string, unknown>,
	signature: CesrSignature
): StepResult {
	const shape = validateInteractionShape(event);
	if (!shape.ok) return shape;
	const xe = shape.value;

	let said: CesrDigest;
	let versionString: string;
	try {
		const computed = computeEventSaid({
			t: 'ixn',
			d: SAID_PLACEHOLDER,
			i: xe.i,
			s: xe.s,
			p: xe.p,
			a: xe.a,
		});
		said = computed.said;
		versionString = computed.versionString;
	} catch (err) {
		if (err instanceof CanonicalJsonError) {
			// A non-JSON-safe anchor in `a` surfaces here.
			return fail({ code: 'NON_CANONICAL_EVENT' });
		}
		throw err;
	}

	if (xe.d !== said) return fail({ code: 'INVALID_EVENT_DIGEST' });
	if (xe.v !== versionString) return fail({ code: 'NON_CANONICAL_EVENT' });
	if ((xe.i as string) !== (state.aid as string)) {
		return fail({
			code: 'INVALID_DID',
			message: 'interaction event `i` does not match the KEL AID',
		});
	}

	const expectedSeq = state.sequenceNumber + 1;
	const seq = Number.parseInt(xe.s, 16);
	if (!Number.isSafeInteger(seq) || seq !== expectedSeq) {
		return fail({ code: 'INVALID_SEQUENCE', expected: expectedSeq, actual: seq });
	}
	if ((xe.p as string) !== (state.lastEventDigest as string)) {
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
			sequenceNumber: seq,
			lastEventDigest: said,
			currentPublicKey: state.currentPublicKey,
			nextKeyCommitment: state.nextKeyCommitment,
			transferable: true,
			eventType: 'ixn',
		},
	};
}
