/**
 * keripy interoperability tests for establishment-only (EO) identifiers.
 *
 * The `EO` configuration trait (`c: ["EO"]`) restricts a KEL to establishment
 * events — `icp` and `rot` — and forbids `ixn`. This file proves the trait
 * round-trips across the node-keri / keripy boundary:
 *
 *   - a node-keri EO KEL (icp + rot + rot) is accepted by keripy, and the two
 *     implementations emit byte-identical EO streams from the same seeds;
 *   - a keripy EO KEL is verified by node-keri, which surfaces the trait in the
 *     replayed state;
 *   - an interaction event keripy appends to an EO inception — well-formed and
 *     correctly signed — is rejected by node-keri's replay on policy grounds
 *     (`ESTABLISHMENT_ONLY_NO_INTERACTION`).
 *
 * Like `keripy-interop.test.ts`, the suite is skipped unless the keripy bridge
 * is provisioned (`bash test/interop/setup-keripy.sh`), and it runs entirely
 * under SHA2-256 — the bridge pins keripy's SAID to node-keri's only digest, so
 * no algorithm registration is needed. See that file's docstring for the wire
 * form and profile-alignment details.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { encodePublicKeyEd25519 } from '../src/cesr/encode';
import { parseDidKeri } from '../src/did/did-keri';
import type { Aid } from '../src/did/did-keri';
import { parseKel } from '../src/event/stream';
import {
	keripyAvailable,
	keripyUnavailableReason,
	keripyGenEoKel,
	keripyGenEoIcpThenIxn,
	keripyVerifyKel,
} from './interop/bridge';

const keripyReady = keripyAvailable();
if (!keripyReady) {
	console.warn(`\n[keripy interop] suite skipped:\n${keripyUnavailableReason()}\n`);
}
const describeInterop = keripyReady ? describe : describe.skip;

/**
 * Seeds shared by both implementations. As in `keripy-interop.test.ts`, the
 * node-keri key for integer seed `n` is `keyPairFromSeed(range(n, n + 32))`,
 * which is exactly the key the bridge's `_signer(n)` derives. Seeds stay in
 * [0, 223] so `n + 31 <= 255`.
 */
const SEEDS = [0, 32, 64, 96];

/** The node-keri keypair for the bridge's integer seed `n`. */
function seedKeyPair(n: number) {
	const raw = new Uint8Array(32);
	for (let i = 0; i < 32; i++) raw[i] = n + i;
	return keyPairFromSeed(raw);
}

/**
 * Build a three-event establishment-only KEL with node-keri: an EO inception
 * followed by two rotations (sequence numbers 0..2). keripy's `gen-eo-kel`
 * builds the structurally identical log from the same seeds.
 */
function buildNodeKeriEoKel() {
	const [k0, k1, k2, k3] = SEEDS.map(seedKeyPair);

	const icp = createIdentifier({
		currentPrivateKey: k0!.privateKey,
		nextPublicKey: k1!.publicKey,
		establishmentOnly: true,
	});
	const rot1 = rotateIdentifier({
		state: icp.state,
		currentPrivateKey: k1!.privateKey,
		nextPublicKey: k2!.publicKey,
	});
	const rot2 = rotateIdentifier({
		state: rot1.state,
		currentPrivateKey: k2!.privateKey,
		nextPublicKey: k3!.publicKey,
	});

	const kel = icp.inceptionEvent + rot1.rotationEvent + rot2.rotationEvent;
	return { did: icp.did, aid: icp.aid, kel, finalState: rot2.state };
}

describeInterop('keripy interop: establishment-only KELs', () => {
	test('a node-keri EO KEL (icp + rot + rot) is accepted by keripy', () => {
		const { aid, kel, finalState } = buildNodeKeriEoKel();

		const result = keripyVerifyKel(aid, kel);

		expect(result.ok).toBe(true);
		if (result.ok) {
			// keripy replayed the whole EO log: digest chain, signatures, and
			// pre-rotation commitments all checked out, and it honoured the `EO`
			// trait rather than rejecting the inception.
			expect(result.sn).toBe(2);
			expect(result.said).toBe(finalState.lastEventDigest);
			expect(result.currentKeys).toEqual([finalState.currentPublicKey]);
		}
	});

	test('node-keri and keripy produce byte-identical EO KEL streams', () => {
		// From the same seeds the two implementations independently emit the
		// same CESR stream — `c: ["EO"]` inception, rotations, and indexed
		// signatures included.
		const { kel } = buildNodeKeriEoKel();
		const generated = keripyGenEoKel(SEEDS);

		expect(kel).toEqual(generated.kel);
	});

	test('a keripy EO KEL is verified by node-keri and surfaces the trait', () => {
		const generated = keripyGenEoKel(SEEDS);

		// The inception keripy emitted carries the EO trait...
		const events = parseKel(generated.kel);
		expect(events).toHaveLength(3);
		const inception = events[0]!.event as unknown as { c: readonly unknown[] };
		expect(inception.c).toEqual(['EO']);

		// ...and replaying it re-derives the AID and reports establishment-only.
		const parsed = parseDidKeri(generated.did);
		expect(parsed.aid).toBe(generated.aid);

		const result = verifyKel({ aid: parsed.aid, kel: generated.kel });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.sequenceNumber).toBe(2);
			expect(result.state.aid).toBe(generated.aid);
			expect(result.state.transferable).toBe(true);
			if (result.state.transferable) {
				expect(result.state.establishmentOnly).toBe(true);
			}
			// The final rotation revealed seed 64; that is the current key.
			expect(result.state.currentPublicKey).toBe(
				encodePublicKeyEd25519(seedKeyPair(64).publicKey.raw)
			);
		}
	});
});

describeInterop('keripy interop: establishment-only enforcement', () => {
	test('node-keri rejects an ixn keripy appended to an EO inception', () => {
		// keripy builds and signs a perfectly well-formed interaction event on
		// top of an EO inception; the bridge appends it without enforcing the
		// trait. node-keri's replay must refuse it on policy grounds.
		const generated = keripyGenEoIcpThenIxn([0, 32], [{ smuggled: true }]);

		// Sanity-check the fixture: an EO inception followed by an `ixn`.
		const events = parseKel(generated.kel);
		expect(events).toHaveLength(2);
		const inception = events[0]!.event as unknown as {
			t: string;
			c: readonly unknown[];
		};
		expect(inception.t).toBe('icp');
		expect(inception.c).toEqual(['EO']);
		expect((events[1]!.event as unknown as { t: string }).t).toBe('ixn');

		const result = verifyKel({
			aid: generated.aid as unknown as Aid,
			kel: generated.kel,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('ESTABLISHMENT_ONLY_NO_INTERACTION');
			if (result.error.code === 'ESTABLISHMENT_ONLY_NO_INTERACTION') {
				expect(result.error.eventType).toBe('ixn');
			}
		}
	});
});
