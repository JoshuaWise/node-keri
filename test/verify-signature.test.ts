import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { deactivateIdentifier } from '../src/api/deactivate-identifier';
import { verifySignature } from '../src/api/verify-signature';
import { decodeSignatureEd25519 } from '../src/cesr/decode';
import { encodeSignatureEd25519 } from '../src/cesr/encode';
import { sign } from '../src/crypto/ed25519';
import { keyPairFromSeed, publicKeyToCesr } from '../src/crypto/keypair';
import type { Aid } from '../src/did/did-keri';
import { utf8Encode } from '../src/bytes/utf8';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const K0 = () => keyPairFromSeed(fillSeed(0x30));
const K1 = () => keyPairFromSeed(fillSeed(0x31));
const K2 = () => keyPairFromSeed(fillSeed(0x32));

const PAYLOAD = utf8Encode('agent-to-agent message body');

function newIdentifier() {
	const currentKeyPair = K0();
	const nextKeyPair = K1();
	const result = createIdentifier({
		currentPrivateKey: currentKeyPair.privateKey,
		nextPublicKey: nextKeyPair.publicKey,
	});
	// Thread the keypairs through so callers can sign with / rotate to them.
	return { ...result, currentKeyPair, nextKeyPair };
}

describe('verifySignature — accepts a valid signature', () => {
	test('verifies a payload signed by the current key', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignature({ aid: id.aid, kel: id.event, payload: PAYLOAD, signature })
		).toBe(true);
	});

	test('tracks key rotation: the new key verifies, the old one does not', () => {
		const id = newIdentifier();
		const rotation = rotateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
			nextPublicKey: K2().publicKey,
		});
		const kel = id.event + rotation.event;

		const byNewKey = encodeSignatureEd25519(sign(id.nextKeyPair.privateKey, PAYLOAD));
		expect(
			verifySignature({ aid: id.aid, kel, payload: PAYLOAD, signature: byNewKey })
		).toBe(true);

		const byOldKey = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignature({ aid: id.aid, kel, payload: PAYLOAD, signature: byOldKey })
		).toBe(false);
	});
});

describe('verifySignature — rejects invalid signatures', () => {
	test('false for a tampered payload', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignature({
				aid: id.aid,
				kel: id.event,
				payload: utf8Encode('a different message'),
				signature,
			})
		).toBe(false);
	});

	test('false for a tampered (but well-formed) signature', () => {
		const id = newIdentifier();
		const raw = decodeSignatureEd25519(
			encodeSignatureEd25519(sign(id.currentKeyPair.privateKey, PAYLOAD))
		);
		raw[0] = raw[0]! ^ 0xff;
		expect(
			verifySignature({
				aid: id.aid,
				kel: id.event,
				payload: PAYLOAD,
				signature: encodeSignatureEd25519(raw),
			})
		).toBe(false);
	});

	test('false for a structurally malformed signature string', () => {
		const id = newIdentifier();
		expect(
			verifySignature({
				aid: id.aid,
				kel: id.event,
				payload: PAYLOAD,
				signature: 'not-a-cesr-signature' as never,
			})
		).toBe(false);
	});

	test('false when the KEL belongs to a different identifier', () => {
		const idA = newIdentifier();
		const idB = createIdentifier({
			currentPrivateKey: K1().privateKey,
			nextPublicKey: K2().publicKey,
		});
		const signature = encodeSignatureEd25519(
			sign(idA.currentKeyPair.privateKey, PAYLOAD)
		);
		expect(
			verifySignature({ aid: idB.aid, kel: idA.event, payload: PAYLOAD, signature })
		).toBe(false);
	});

	test('false for a transferable AID given the empty-string "no KEL" value', () => {
		const id = newIdentifier();
		const signature = encodeSignatureEd25519(
			sign(id.currentKeyPair.privateKey, PAYLOAD)
		);
		// A transferable identifier's key state lives in its KEL; the
		// empty-string "no KEL" value leaves nothing to establish the key from.
		expect(
			verifySignature({ aid: id.aid, kel: '', payload: PAYLOAD, signature })
		).toBe(false);
	});

	test('false once the identifier has been deactivated', () => {
		const id = newIdentifier();
		const deact = deactivateIdentifier({
			state: id.state,
			newPrivateKey: id.nextKeyPair.privateKey,
		});
		const kel = id.event + deact.event;
		// The deactivation reveals (and is signed by) the pre-rotated key; even a
		// signature it produced is no longer trusted once abandoned.
		const signature = encodeSignatureEd25519(
			sign(id.nextKeyPair.privateKey, PAYLOAD)
		);
		expect(verifySignature({ aid: id.aid, kel, payload: PAYLOAD, signature })).toBe(
			false
		);
	});
});

describe('verifySignature — non-transferable AID', () => {
	// A non-transferable AID *is* the signing key — a `B`-coded basic prefix,
	// self-certifying, so it verifies with the empty-string "no KEL" value.
	// Build one by swapping the code char of a `D` key (equivalently
	// `encodeNonTransferablePublicKeyEd25519`): same raw bytes, the `B` code.
	const kp = keyPairFromSeed(fillSeed(0x44));
	const ntAid = ('B' + publicKeyToCesr(kp.publicKey).slice(1)) as Aid;

	test('verifies a signature with the empty-string "no KEL" value', () => {
		const signature = encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD));
		expect(
			verifySignature({ aid: ntAid, kel: '', payload: PAYLOAD, signature })
		).toBe(true);
	});

	test('false for a signature by a different key', () => {
		const other = keyPairFromSeed(fillSeed(0x45));
		const signature = encodeSignatureEd25519(sign(other.privateKey, PAYLOAD));
		expect(
			verifySignature({ aid: ntAid, kel: '', payload: PAYLOAD, signature })
		).toBe(false);
	});

	test('false when given a malformed KEL instead of the empty string', () => {
		// A non-empty `kel` is always replayed — even for a non-transferable AID —
		// so a bogus one fails rather than being silently ignored.
		const signature = encodeSignatureEd25519(sign(kp.privateKey, PAYLOAD));
		expect(
			verifySignature({
				aid: ntAid,
				kel: 'not-a-real-kel',
				payload: PAYLOAD,
				signature,
			})
		).toBe(false);
	});
});

describe('verifySignature — argument contract', () => {
	const id = newIdentifier();
	const signature = encodeSignatureEd25519(sign(id.currentKeyPair.privateKey, PAYLOAD));
	const base = { aid: id.aid, kel: id.event, payload: PAYLOAD, signature };

	test('throws on a non-object input', () => {
		expect(() => verifySignature(null as never)).toThrow(InvalidArgumentError);
	});

	test('throws when aid is not a non-empty string', () => {
		expect(() => verifySignature({ ...base, aid: '' as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when kel is not a string', () => {
		expect(() => verifySignature({ ...base, kel: {} as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when payload is not a Uint8Array', () => {
		expect(() => verifySignature({ ...base, payload: 'text' as never })).toThrow(
			InvalidArgumentError
		);
	});

	test('throws when signature is not a string', () => {
		expect(() => verifySignature({ ...base, signature: 123 as never })).toThrow(
			InvalidArgumentError
		);
	});
});
