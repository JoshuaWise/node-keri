/**
 * CESR stream framing for signed KERI events.
 *
 * KERI does not carry a signed event as a JSON `{ event, signatures }` wrapper.
 * The wire form is a *CESR stream*: the event's canonical JSON bytes followed
 * immediately by an attachment group — a counter naming how many controller
 * signatures follow, then the indexed signatures themselves. A KEL is simply
 * the frames of its events concatenated, with no separators: the version
 * string inside each event declares that event's exact byte length, and each
 * indexed signature is fixed-length, so a parser always knows where one frame
 * ends and the next begins.
 *
 *   {"v":"KERI10JSON0000fb_","t":"icp",...}-AABAA<86 base64 chars>
 *   └──────────── event JSON (size from `v`) ───────────┘└┬─┘└────┬────┘
 *                                          counter (-A, count 1) ─┘    │
 *                                             one indexed signature ───┘
 *
 * This module is the codec for that form. `encodeEventFrame` turns an
 * in-memory `SignedKeriEvent` into its frame string; `parseSignedEvent` /
 * `parseKel` turn frames back into `SignedKeriEvent`s for inspection. The
 * KEL replay verifier parses streams through `parseStreamResult`.
 */

import { utf8Decode, utf8Encode } from '../bytes/utf8';
import { CESR_INDEXED_SIGNATURE_ED25519 } from '../cesr/codes';
import {
	CONTROLLER_IDX_SIGS_LENGTH,
	encodeControllerSigCount,
	parseCounter,
} from '../cesr/counter';
import { decodeIndexedSignatureEd25519 } from '../cesr/decode';
import { CesrIndexedSignature } from '../cesr/qualified';
import { MalformedInputError } from '../profile/errors';
import { KERI_VERSION_STRING_LENGTH } from './digest';
import { serializeEvent } from './sign';
import { SignedKeriEvent } from './types';

/** Character length of one indexed Ed25519 signature (a "Siger"). */
const SIGER_LENGTH = CESR_INDEXED_SIGNATURE_ED25519.fs;

/** The literal bytes every KERI 1.0 JSON event begins with. */
const VERSION_PREFIX = '{"v":"KERI10JSON';

/**
 * Smallest possible event header: `{"v":"` + `KERI10JSON` + 6 hex size chars
 * + `_`. The whole event is at least this long, so the size field is always
 * readable once this many bytes are present.
 */
const HEADER_LENGTH = 6 + KERI_VERSION_STRING_LENGTH;

/**
 * Serialize one signed event to its CESR stream frame.
 *
 * The event is serialized through `serializeEvent` (canonical field order,
 * canonical JSON), then the controller's indexed signatures are appended
 * behind a `-A` counter. Concatenating the frames of a KEL's events — in
 * order — yields the KEL's wire form.
 *
 * The encoder fails closed on a malformed input rather than emitting a corrupt
 * stream. `encodeEventFrame` is exported and may be reached through untyped
 * (`as any`, JSON) paths, so every part of `signed` is re-validated at runtime:
 *
 *   - the event must serialize to bytes whose length matches the size its own
 *     version string declares — otherwise the frame is self-contradicting and
 *     the parser, which trusts `v` to locate the attachment, would mis-frame it;
 *   - every signature must be a well-formed *indexed* Ed25519 signature at key
 *     index 0 (this single-key profile permits no other index), guaranteeing
 *     each siger is exactly `SIGER_LENGTH` characters and re-parseable.
 *
 * A defect throws `MalformedInputError`; a valid `SignedKeriEvent` always round-
 * trips through `parseSignedEvent`.
 */
export function encodeEventFrame(signed: SignedKeriEvent): string {
	if (signed === null || typeof signed !== 'object') {
		throw new MalformedInputError('encodeEventFrame requires a signed event');
	}
	// Typed as a 1-tuple, but `encodeEventFrame` may be reached through untyped
	// paths — treat `signatures` as an unknown array and validate at runtime.
	const signatures = signed.signatures as readonly unknown[];
	if (!Array.isArray(signatures) || signatures.length === 0) {
		throw new MalformedInputError('signed event has no signatures');
	}

	const eventBytes = serializeEvent(signed.event);
	// The event's version string declares its own byte length, and the frame
	// parser trusts that to find where the attachment begins. Refuse to emit a
	// frame whose `v` size disagrees with the bytes actually serialized — that
	// is a wire artifact no parser could read back. `readEventSize` also
	// rejects a missing or malformed version string here.
	const declaredSize = readEventSize(eventBytes, 0);
	if (declaredSize !== eventBytes.length) {
		throw new MalformedInputError(
			`event version string declares ${declaredSize} bytes but the event `
				+ `serializes to ${eventBytes.length}`
		);
	}

	let attachment = encodeControllerSigCount(signatures.length);
	for (const sig of signatures) {
		if (typeof sig !== 'string') {
			throw new MalformedInputError('signature must be a CESR-qualified string');
		}
		// Validate every signature is a real indexed Ed25519 siger before it
		// goes on the wire: a bad code, length, base64, or pad bit throws here
		// rather than producing a frame that cannot be parsed back.
		const { index } = decodeIndexedSignatureEd25519(sig);
		if (index !== 0) {
			throw new MalformedInputError(
				`signature index must be 0 in this single-key profile, got ${index}`
			);
		}
		attachment += sig;
	}
	return utf8Decode(eventBytes) + attachment;
}

/** Result of parsing a CESR stream — events, or the framing defect found. */
export type ParseStreamResult =
	| { ok: true; events: SignedKeriEvent[] }
	| { ok: false; message: string };

/** Render the ASCII text in `bytes[start, end)`, rejecting any non-ASCII byte. */
function asciiSlice(bytes: Uint8Array, start: number, end: number): string {
	let text = '';
	for (let i = start; i < end; i++) {
		const byte = bytes[i];
		if (byte === undefined) {
			throw new MalformedInputError('truncated CESR stream');
		}
		if (byte >= 0x80) {
			throw new MalformedInputError('non-ASCII byte in CESR attachment');
		}
		text += String.fromCharCode(byte);
	}
	return text;
}

/** Read the event byte length declared by the version string at `offset`. */
function readEventSize(bytes: Uint8Array, offset: number): number {
	if (offset + HEADER_LENGTH > bytes.length) {
		throw new MalformedInputError('truncated event header');
	}
	const head = asciiSlice(bytes, offset, offset + HEADER_LENGTH);
	if (!head.startsWith(VERSION_PREFIX)) {
		throw new MalformedInputError('frame does not begin with a KERI JSON event');
	}
	if (head[HEADER_LENGTH - 1] !== '_') {
		throw new MalformedInputError('malformed KERI version string');
	}
	const hex = head.slice(VERSION_PREFIX.length, HEADER_LENGTH - 1);
	if (!/^[0-9a-f]{6}$/.test(hex)) {
		throw new MalformedInputError('malformed version-string size field');
	}
	const size = Number.parseInt(hex, 16);
	if (size < HEADER_LENGTH) {
		throw new MalformedInputError('event size is smaller than its own header');
	}
	if (offset + size > bytes.length) {
		throw new MalformedInputError('event size runs past the end of the stream');
	}
	return size;
}

/** Parse one frame starting at byte `offset`; report the next frame's offset. */
function parseFrameAt(
	bytes: Uint8Array,
	offset: number
): { signed: SignedKeriEvent; nextOffset: number } {
	const size = readEventSize(bytes, offset);

	let event: unknown;
	try {
		event = JSON.parse(utf8Decode(bytes.subarray(offset, offset + size)));
	} catch {
		throw new MalformedInputError('event is not valid JSON');
	}
	if (event === null || typeof event !== 'object' || Array.isArray(event)) {
		throw new MalformedInputError('event must be a JSON object');
	}

	const attachOffset = offset + size;
	const counterText = asciiSlice(
		bytes,
		attachOffset,
		attachOffset + CONTROLLER_IDX_SIGS_LENGTH
	);
	const { count, consumed } = parseCounter(counterText, 0);

	const signatures: CesrIndexedSignature[] = [];
	let sigOffset = attachOffset + consumed;
	for (let i = 0; i < count; i++) {
		const sig = asciiSlice(bytes, sigOffset, sigOffset + SIGER_LENGTH);
		signatures.push(sig as CesrIndexedSignature);
		sigOffset += SIGER_LENGTH;
	}

	const signed = { event, signatures } as unknown as SignedKeriEvent;
	return { signed, nextOffset: sigOffset };
}

/**
 * Parse a CESR stream into its signed events, never throwing.
 *
 * A framing defect — a bad version string, a truncated event, an unsupported
 * counter, a short signature — is returned as `{ ok: false, message }`. The
 * events themselves are *not* semantically validated here: that is the replay
 * verifier's job. This is the entry point `verifyKel` uses, so a malformed
 * wire form becomes a `MALFORMED_STREAM` verification result, not an
 * exception.
 */
export function parseStreamResult(stream: string): ParseStreamResult {
	if (typeof stream !== 'string') {
		return { ok: false, message: 'stream must be a string' };
	}
	const bytes = utf8Encode(stream);
	const events: SignedKeriEvent[] = [];
	let offset = 0;
	while (offset < bytes.length) {
		try {
			const { signed, nextOffset } = parseFrameAt(bytes, offset);
			events.push(signed);
			offset = nextOffset;
		} catch (err) {
			if (err instanceof MalformedInputError) {
				return { ok: false, message: err.message };
			}
			throw err;
		}
	}
	return { ok: true, events };
}

/**
 * Parse a CESR stream (a KEL, or any concatenation of event frames) into its
 * signed events. Throws `MalformedInputError` on a framing defect.
 *
 * This is a low-level inspection helper: the events it returns are structural
 * only and carry no verification guarantee — pass the stream to `verifyKel`
 * for that.
 */
export function parseKel(stream: string): SignedKeriEvent[] {
	const result = parseStreamResult(stream);
	if (!result.ok) {
		throw new MalformedInputError(result.message);
	}
	return result.events;
}

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
