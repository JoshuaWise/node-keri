/**
 * `verifyKel` — the public entry point for KEL verification.
 *
 * This is a thin wrapper around `replayKel`: it enforces the *argument*
 * contract (throwing `InvalidArgumentError` for a caller that passes the wrong
 * shape entirely) and then delegates to the replay verifier, which returns a
 * discriminated result for every data-level failure.
 *
 * The split mirrors the error policy of the library: throwing is reserved for
 * programmer errors, while anything that could legitimately arrive from an
 * untrusted source — a malformed, tampered, reordered, or hostile KEL — is a
 * `{ ok: false, error }` result the caller is expected to handle.
 */

import { Aid } from '../did/did-keri';
import { InvalidArgumentError } from '../profile/errors';
import { VerifyKelResult, replayKel } from '../kel/replay';

export type { VerifyKelResult } from '../kel/replay';

export interface VerifyKelInput {
	/** The identifier the caller expects this KEL to belong to. */
	readonly aid: Aid;
	/**
	 * The full key event log as a CESR stream — the event frames, inception
	 * first, concatenated in order. Build one by joining the wire-form events
	 * returned by `createIdentifier` / `rotateIdentifier` / `interactIdentifier`.
	 */
	readonly kel: string;
}

/**
 * Verify a key event log and reconstruct its latest authoritative state.
 *
 * On success the returned `state` is the only `KeriState` in the library a
 * caller may treat as verified — it was derived solely by replaying `events`
 * from inception, never trusted from the input.
 */
export function verifyKel(input: VerifyKelInput): VerifyKelResult {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('verifyKel requires an input object');
	}
	if (typeof input.aid !== 'string' || input.aid.length === 0) {
		throw new InvalidArgumentError('verifyKel requires a non-empty `aid` string');
	}
	if (typeof input.kel !== 'string') {
		throw new InvalidArgumentError('verifyKel requires a `kel` string');
	}
	return replayKel(input.aid, input.kel);
}
