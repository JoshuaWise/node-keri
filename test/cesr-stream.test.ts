/**
 * Indexed signatures, counters, and CESR stream framing.
 *
 * Covers the wire-format layer added for keripy interoperability: the indexed
 * Ed25519 signature ("Siger", code `A`), the `-A` controller-signature counter,
 * the integer↔base64 helpers behind both, and the event-frame codec that turns
 * a `SignedKeriEvent` into its CESR stream form and back.
 */

import { b64ToInt, intToB64 } from '../src/bytes/base64url';
import { decodeIndexedSignatureEd25519, signatureIndex } from '../src/cesr/decode';
import {
	encodeIndexedSignatureEd25519,
	encodeSignatureEd25519,
} from '../src/cesr/encode';
import {
	CONTROLLER_IDX_SIGS_CODE,
	encodeControllerSigCount,
	parseCounter,
} from '../src/cesr/counter';
import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { encodeEventFrame, parseKel, parseSignedEvent } from '../src/event/stream';
import { InvalidArgumentError, MalformedInputError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

function sig64(byte: number): Uint8Array {
	return new Uint8Array(64).fill(byte);
}

describe('intToB64 / b64ToInt', () => {
	test('round-trips small integers at a fixed width', () => {
		for (let n = 0; n < 64; n++) {
			expect(b64ToInt(intToB64(n, 1))).toBe(n);
		}
		for (const n of [0, 1, 63, 64, 100, 4095]) {
			expect(b64ToInt(intToB64(n, 2))).toBe(n);
		}
	});

	test('intToB64 pads to the requested width', () => {
		expect(intToB64(0, 1)).toBe('A');
		expect(intToB64(0, 2)).toBe('AA');
		expect(intToB64(1, 2)).toBe('AB');
	});

	test('intToB64 rejects a value too large for the width', () => {
		expect(() => intToB64(64, 1)).toThrow(MalformedInputError);
		expect(() => intToB64(-1, 1)).toThrow(MalformedInputError);
	});

	test('b64ToInt rejects a non-alphabet character', () => {
		expect(() => b64ToInt('*')).toThrow(MalformedInputError);
		expect(() => b64ToInt('')).toThrow(MalformedInputError);
	});
});

describe('indexed Ed25519 signatures (Siger)', () => {
	test('round-trips raw bytes and index for every single-char index', () => {
		for (const index of [0, 1, 7, 31, 63]) {
			const raw = sig64(index + 1);
			const qb64 = encodeIndexedSignatureEd25519(raw, index);
			expect(qb64.length).toBe(88);
			expect(qb64[0]).toBe('A');
			const decoded = decodeIndexedSignatureEd25519(qb64);
			expect(decoded.index).toBe(index);
			expect(Array.from(decoded.raw)).toEqual(Array.from(raw));
			expect(signatureIndex(qb64)).toBe(index);
		}
	});

	test('index 0 encodes as the `AA` prefix', () => {
		expect(encodeIndexedSignatureEd25519(sig64(9), 0).startsWith('AA')).toBe(true);
	});

	test('rejects an index outside 0..63', () => {
		expect(() => encodeIndexedSignatureEd25519(sig64(1), 64)).toThrow(
			InvalidArgumentError
		);
		expect(() => encodeIndexedSignatureEd25519(sig64(1), -1)).toThrow(
			InvalidArgumentError
		);
	});

	test('rejects a raw payload of the wrong length', () => {
		expect(() => encodeIndexedSignatureEd25519(new Uint8Array(63), 0)).toThrow(
			InvalidArgumentError
		);
	});

	test('decode rejects a non-indexed (0B) signature', () => {
		const cigar = encodeSignatureEd25519(sig64(3));
		expect(() => decodeIndexedSignatureEd25519(cigar)).toThrow(MalformedInputError);
	});

	test('decode rejects a wrong-length string', () => {
		expect(() => decodeIndexedSignatureEd25519('AA' + 'A'.repeat(85))).toThrow(
			MalformedInputError
		);
	});
});

describe('controller-signature counter', () => {
	test('round-trips a count through encode/parse', () => {
		for (const count of [1, 2, 5, 63, 100]) {
			const encoded = encodeControllerSigCount(count);
			expect(encoded.length).toBe(4);
			expect(encoded.startsWith(CONTROLLER_IDX_SIGS_CODE)).toBe(true);
			const parsed = parseCounter(encoded, 0);
			expect(parsed.count).toBe(count);
			expect(parsed.consumed).toBe(4);
		}
	});

	test('encode rejects a non-positive count', () => {
		expect(() => encodeControllerSigCount(0)).toThrow(InvalidArgumentError);
	});

	test('parse rejects an unsupported counter code', () => {
		// `-B` would introduce witness signatures — out of profile.
		expect(() => parseCounter('-BAB', 0)).toThrow(MalformedInputError);
	});

	test('parse rejects a truncated counter', () => {
		expect(() => parseCounter('-A', 0)).toThrow(MalformedInputError);
	});
});

describe('event-frame codec', () => {
	const k1 = keyPairFromSeed(fillSeed(0x12));
	const id = createIdentifier({
		currentPrivateKey: keyPairFromSeed(fillSeed(0x11)).privateKey,
		nextPublicKey: k1.publicKey,
	});

	test('a constructor frame round-trips through parse and re-encode', () => {
		const parsed = parseSignedEvent(id.event);
		expect(parsed.event.t).toBe('icp');
		expect(parsed.signatures).toHaveLength(1);
		expect(encodeEventFrame(parsed)).toBe(id.event);
	});

	test('a frame is the event JSON followed by a `-AAB` attachment', () => {
		const parsed = parseSignedEvent(id.event);
		expect(id.event.startsWith('{"v":"KERI10JSON')).toBe(true);
		expect(id.event).toContain('-AAB' + parsed.signatures[0]);
	});

	test('parseKel splits a concatenated multi-event stream', () => {
		const rot = rotateIdentifier({
			state: id.state,
			currentPrivateKey: k1.privateKey,
			nextPublicKey: keyPairFromSeed(fillSeed(0x13)).publicKey,
		});
		const stream = id.event + rot.event;
		const events = parseKel(stream);
		expect(events).toHaveLength(2);
		expect(events[0]!.event.t).toBe('icp');
		expect(events[1]!.event.t).toBe('rot');
	});

	test('parseSignedEvent rejects trailing bytes after one frame', () => {
		expect(() => parseSignedEvent(id.event + 'xx')).toThrow(
			MalformedInputError
		);
	});

	test('parseKel rejects a stream whose version size is wrong', () => {
		const f = id.event;
		const broken = f.slice(0, 16) + '000000' + f.slice(22);
		expect(() => parseKel(broken)).toThrow(MalformedInputError);
	});

	test('parseKel rejects an empty trailing/garbage frame', () => {
		expect(() => parseKel(id.event + 'not-a-frame')).toThrow(
			MalformedInputError
		);
	});

	test('parseKel of an empty string yields no events', () => {
		expect(parseKel('')).toEqual([]);
	});
});

describe('encodeEventFrame — robust serialization', () => {
	const id = createIdentifier({
		currentPrivateKey: keyPairFromSeed(fillSeed(0x21)).privateKey,
		nextPublicKey: keyPairFromSeed(fillSeed(0x22)).publicKey,
	});
	const signed = parseSignedEvent(id.event);

	test('rejects a non-object signed event', () => {
		expect(() => encodeEventFrame(null as never)).toThrow(MalformedInputError);
		expect(() => encodeEventFrame('frame' as never)).toThrow(MalformedInputError);
	});

	test('rejects a signed event with no signatures', () => {
		expect(() =>
			encodeEventFrame({ event: signed.event, signatures: [] as never })
		).toThrow(MalformedInputError);
	});

	test('rejects a non-string signature', () => {
		expect(() =>
			encodeEventFrame({ event: signed.event, signatures: [42] as never })
		).toThrow(MalformedInputError);
	});

	test('rejects a signature that is not a well-formed siger', () => {
		expect(() =>
			encodeEventFrame({
				event: signed.event,
				signatures: ['AA' + 'A'.repeat(40)] as never,
			})
		).toThrow(MalformedInputError);
	});

	test('rejects a non-indexed (0B Cigar) signature', () => {
		const cigar = encodeSignatureEd25519(sig64(7));
		expect(() =>
			encodeEventFrame({ event: signed.event, signatures: [cigar] as never })
		).toThrow(MalformedInputError);
	});

	test('rejects a signature at a non-zero key index', () => {
		const indexed = encodeIndexedSignatureEd25519(sig64(7), 3);
		expect(() =>
			encodeEventFrame({ event: signed.event, signatures: [indexed] as never })
		).toThrow(/index must be 0/);
	});

	test('rejects an event whose version string size is wrong', () => {
		// Mutate one hex digit of the `v` size so the declared length no longer
		// matches the bytes the event actually serializes to.
		const v = signed.event.v;
		const hi = v.slice(0, 10) + (v[10] === '0' ? '1' : '0') + v.slice(11);
		expect(() =>
			encodeEventFrame({
				event: { ...signed.event, v: hi } as never,
				signatures: signed.signatures,
			})
		).toThrow(MalformedInputError);
	});

	test('rejects an event of an unserializable type', () => {
		expect(() =>
			encodeEventFrame({
				event: { ...signed.event, t: 'xxx' } as never,
				signatures: signed.signatures,
			})
		).toThrow();
	});

	test('a well-formed signed event round-trips through parse', () => {
		const frame = encodeEventFrame(signed);
		expect(frame).toBe(id.event);
		expect(parseSignedEvent(frame)).toEqual(signed);
	});
});
