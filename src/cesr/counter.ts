/**
 * CESR counter codes.
 *
 * A counter is a framing primitive: it introduces a *group* of following
 * primitives and says how many there are. It is not a Matter primitive — it
 * carries no raw payload, only a code and a count — so it has its own tiny
 * codec rather than going through `encodeMatter` / `decodeMatter`.
 *
 * This profile recognizes exactly one counter: `-A`, "ControllerIdxSigs",
 * which precedes the controller's indexed signatures attached to a KEL event.
 * Its qualified form is the 2-character code `-A` followed by a 2-character
 * base64 count — 4 characters total. Every other counter (witness signatures,
 * receipt couples, CESR version groups, …) names an out-of-profile feature and
 * is rejected by `parseCounter`.
 */

import { b64ToInt, intToB64 } from '../bytes/base64url';
import { InvalidArgumentError, MalformedInputError } from '../profile/errors';

/** The "ControllerIdxSigs" counter code — the only counter in this profile. */
export const CONTROLLER_IDX_SIGS_CODE = '-A';

/** Soft (count) size, in characters. */
const COUNT_SIZE = 2;

/** Total character length of a `-A` counter. */
export const CONTROLLER_IDX_SIGS_LENGTH = CONTROLLER_IDX_SIGS_CODE.length + COUNT_SIZE;

/** Largest count representable in the 2-character base64 soft field. */
const MAX_COUNT = 64 * 64 - 1;

/**
 * Encode a "ControllerIdxSigs" counter introducing `count` indexed signatures.
 * `count` must be a positive integer that fits the 2-character count field.
 */
export function encodeControllerSigCount(count: number): string {
	if (!Number.isInteger(count) || count < 1 || count > MAX_COUNT) {
		throw new InvalidArgumentError(
			`controller signature count must be an integer in [1, ${MAX_COUNT}], got ${count}`
		);
	}
	return CONTROLLER_IDX_SIGS_CODE + intToB64(count, COUNT_SIZE);
}

/**
 * Read a `-A` counter from `text` at `offset`.
 *
 * Returns the decoded `count` and the number of characters `consumed`. Throws
 * `MalformedInputError` when there are too few characters, the code is not
 * `-A` (any other counter is an out-of-profile feature), or the count field is
 * not valid base64.
 */
export function parseCounter(
	text: string,
	offset: number
): { count: number; consumed: number } {
	if (offset + CONTROLLER_IDX_SIGS_LENGTH > text.length) {
		throw new MalformedInputError('truncated CESR counter');
	}
	const code = text.slice(offset, offset + CONTROLLER_IDX_SIGS_CODE.length);
	if (code !== CONTROLLER_IDX_SIGS_CODE) {
		throw new MalformedInputError(
			`unsupported CESR counter code '${code}': only controller indexed `
				+ `signatures ('${CONTROLLER_IDX_SIGS_CODE}') are supported`
		);
	}
	const count = b64ToInt(
		text.slice(
			offset + CONTROLLER_IDX_SIGS_CODE.length,
			offset + CONTROLLER_IDX_SIGS_LENGTH
		)
	);
	return { count, consumed: CONTROLLER_IDX_SIGS_LENGTH };
}
