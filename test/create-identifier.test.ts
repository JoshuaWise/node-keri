import { createIdentifier } from '../src/api/create-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { generateKeyPair } from '../src/crypto/keypair';
import { formatDidKeri } from '../src/did/did-keri';
import { InvalidArgumentError } from '../src/profile/errors';
import { parseSignedEvent, fillSeed, keyPairFromSeed } from './helpers/util';

const SEED_CURRENT = fillSeed(0x10);
const SEED_NEXT = fillSeed(0x11);

describe('createIdentifier', () => {
	test('produces a consistent did/aid/event/state bundle', () => {
		const currentKeyPair = keyPairFromSeed(SEED_CURRENT);
		const nextKeyPair = keyPairFromSeed(SEED_NEXT);

		const result = createIdentifier({
			currentPrivateKey: currentKeyPair.privateKey,
			nextPublicKey: nextKeyPair.publicKey,
		});

		expect(result.did).toBe(formatDidKeri(result.aid));
		expect(result.aid).toBe(result.state.aid);
		expect(result.did).toBe(result.state.did);
		const inception = parseSignedEvent(result.event);
		expect(inception.event.t).toBe('icp');
		expect(inception.event.s).toBe('0');
		expect(result.state.lastSequenceNumber).toBe(0);
	});

	test('returns no key material — the caller already holds it', () => {
		const result = createIdentifier({
			currentPrivateKey: keyPairFromSeed(SEED_CURRENT).privateKey,
			nextPublicKey: keyPairFromSeed(SEED_NEXT).publicKey,
		});
		expect(result).not.toHaveProperty('currentKeyPair');
		expect(result).not.toHaveProperty('nextKeyPair');
		expect(Object.keys(result).sort()).toEqual(
			['aid', 'did', 'event', 'state'].sort()
		);
	});

	test('is deterministic for fixed seeds', () => {
		const a = createIdentifier({
			currentPrivateKey: keyPairFromSeed(SEED_CURRENT).privateKey,
			nextPublicKey: keyPairFromSeed(SEED_NEXT).publicKey,
		});
		const b = createIdentifier({
			currentPrivateKey: keyPairFromSeed(SEED_CURRENT).privateKey,
			nextPublicKey: keyPairFromSeed(SEED_NEXT).publicKey,
		});
		expect(b.did).toBe(a.did);
		expect(b.event).toEqual(a.event);
	});

	test('the inception event verifies as a one-event KEL', () => {
		const result = createIdentifier({
			currentPrivateKey: keyPairFromSeed(SEED_CURRENT).privateKey,
			nextPublicKey: keyPairFromSeed(SEED_NEXT).publicKey,
		});
		const verified = verifyIdentifier({
			aid: result.aid,
			kel: result.event,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		// Replayed state must match the state returned by the constructor.
		expect(verified.state).toEqual(result.state);
	});

	test('two distinct keypairs mint distinct identifiers', () => {
		const a = createIdentifier({
			currentPrivateKey: generateKeyPair().privateKey,
			nextPublicKey: generateKeyPair().publicKey,
		});
		const b = createIdentifier({
			currentPrivateKey: generateKeyPair().privateKey,
			nextPublicKey: generateKeyPair().publicKey,
		});
		expect(a.did).not.toBe(b.did);
		const verified = verifyIdentifier({ aid: a.aid, kel: a.event });
		expect(verified.ok).toBe(true);
	});
});

describe('createIdentifier — rejects bad input', () => {
	test('throws when the current and next keys are identical', () => {
		const keyPair = keyPairFromSeed(SEED_CURRENT);
		expect(() =>
			createIdentifier({
				currentPrivateKey: keyPair.privateKey,
				nextPublicKey: keyPair.publicKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('throws when two distinct objects hold the same key', () => {
		const seed = fillSeed(0x55);
		expect(() =>
			createIdentifier({
				currentPrivateKey: keyPairFromSeed(seed).privateKey,
				nextPublicKey: keyPairFromSeed(seed).publicKey,
			})
		).toThrow(/distinct keys/);
	});

	test('throws on a non-object input', () => {
		expect(() => createIdentifier(null as never)).toThrow(InvalidArgumentError);
		expect(() => createIdentifier('nope' as never)).toThrow(InvalidArgumentError);
	});

	test('throws when required keys are missing', () => {
		expect(() => createIdentifier({} as never)).toThrow(InvalidArgumentError);
		expect(() =>
			createIdentifier({
				currentPrivateKey: generateKeyPair().privateKey,
			} as never)
		).toThrow(InvalidArgumentError);
	});

	test('rejects a malformed current private key', () => {
		expect(() =>
			createIdentifier({
				currentPrivateKey: {} as never,
				nextPublicKey: generateKeyPair().publicKey,
			})
		).toThrow(InvalidArgumentError);
	});

	test('rejects a malformed next public key', () => {
		expect(() =>
			createIdentifier({
				currentPrivateKey: generateKeyPair().privateKey,
				nextPublicKey: {} as never,
			})
		).toThrow(InvalidArgumentError);
	});
});
