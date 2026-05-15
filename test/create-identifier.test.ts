import { createIdentifier } from '../src/api/create-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { generateKeyPair, keyPairFromSeed } from '../src/crypto/keypair';
import { formatDidKeri } from '../src/did/did-keri';
import { parseSignedEvent } from '../src/event/stream';
import { InvalidArgumentError } from '../src/profile/errors';

function fillSeed(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

const SEED_CURRENT = fillSeed(0x10);
const SEED_NEXT = fillSeed(0x11);

describe('createIdentifier — with supplied keypairs', () => {
	test('produces a consistent did/aid/event/state bundle', () => {
		const currentKeyPair = keyPairFromSeed(SEED_CURRENT);
		const nextKeyPair = keyPairFromSeed(SEED_NEXT);

		const result = createIdentifier({ currentKeyPair, nextKeyPair });

		expect(result.did).toBe(formatDidKeri(result.aid));
		expect(result.aid).toBe(result.state.aid);
		expect(result.did).toBe(result.state.did);
		expect(result.currentKeyPair).toBe(currentKeyPair);
		expect(result.nextKeyPair).toBe(nextKeyPair);
		const inception = parseSignedEvent(result.inceptionEvent);
		expect(inception.event.t).toBe('icp');
		expect(inception.event.s).toBe('0');
		expect(result.state.sequenceNumber).toBe(0);
	});

	test('is deterministic for fixed seeds', () => {
		const a = createIdentifier({
			currentKeyPair: keyPairFromSeed(SEED_CURRENT),
			nextKeyPair: keyPairFromSeed(SEED_NEXT),
		});
		const b = createIdentifier({
			currentKeyPair: keyPairFromSeed(SEED_CURRENT),
			nextKeyPair: keyPairFromSeed(SEED_NEXT),
		});
		expect(b.did).toBe(a.did);
		expect(b.inceptionEvent).toEqual(a.inceptionEvent);
	});

	test('the inception event verifies as a one-event KEL', () => {
		const result = createIdentifier({
			currentKeyPair: keyPairFromSeed(SEED_CURRENT),
			nextKeyPair: keyPairFromSeed(SEED_NEXT),
		});
		const verified = verifyKel({
			aid: result.aid,
			kel: result.inceptionEvent,
		});
		expect(verified.ok).toBe(true);
		if (!verified.ok) throw new Error('unreachable');
		// Replayed state must match the state returned by the constructor.
		expect(verified.state).toEqual(result.state);
	});
});

describe('createIdentifier — generated keypairs', () => {
	test('generates fresh keys when none are supplied', () => {
		const result = createIdentifier();
		expect(result.currentKeyPair.publicKey.raw).toHaveLength(32);
		expect(result.nextKeyPair.publicKey.raw).toHaveLength(32);
		const verified = verifyKel({
			aid: result.aid,
			kel: result.inceptionEvent,
		});
		expect(verified.ok).toBe(true);
	});

	test('two no-argument calls mint distinct identifiers', () => {
		expect(createIdentifier().did).not.toBe(createIdentifier().did);
	});
});

describe('createIdentifier — rejects bad input', () => {
	test('throws when current and next keypairs are identical', () => {
		const keyPair = keyPairFromSeed(SEED_CURRENT);
		expect(() =>
			createIdentifier({ currentKeyPair: keyPair, nextKeyPair: keyPair })
		).toThrow(InvalidArgumentError);
	});

	test('throws when two distinct objects hold the same key', () => {
		const seed = fillSeed(0x55);
		expect(() =>
			createIdentifier({
				currentKeyPair: keyPairFromSeed(seed),
				nextKeyPair: keyPairFromSeed(seed),
			})
		).toThrow(/distinct keys/);
	});

	test('throws on a non-object input', () => {
		expect(() => createIdentifier(null as never)).toThrow(InvalidArgumentError);
		expect(() => createIdentifier('nope' as never)).toThrow(InvalidArgumentError);
	});

	test('rejects a malformed keypair', () => {
		expect(() =>
			createIdentifier({
				currentKeyPair: {} as never,
				nextKeyPair: generateKeyPair(),
			})
		).toThrow(InvalidArgumentError);
	});
});
