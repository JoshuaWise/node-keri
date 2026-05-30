import { createHash } from 'node:crypto';
import { SignedKeriEvent } from '../../src/event/types';
import { parseKel } from '../../src/event/stream';
import { MalformedInputError } from '../../src/profile/errors';

/**
 * Parse a single event frame into its `SignedKeriEvent`. Throws
 * `MalformedInputError` if `frame` is not exactly one well-formed frame
 * (trailing bytes, or no event, are rejected).
 *
 * Like `parseKel`, this is for inspecting the in-memory shape of a wire-form
 * event; it does not verify the event.
 */
export function parseSignedEvent(frame: string): SignedKeriEvent {
	const events = parseKel(frame);
	if (events.length !== 1) {
		throw new MalformedInputError(
			`expected exactly one event frame, parsed ${events.length}`
		);
	}
	return events[0]!;
}

export function sha256(input: Readonly<Uint8Array>): Uint8Array {
	return new Uint8Array(createHash('sha256').update(input).digest());
}

export function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}
