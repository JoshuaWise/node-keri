/**
 * Cross-implementation interoperability tests against keripy.
 *
 * keripy (the `keri` PyPI package) is the reference KERI implementation. These
 * tests prove that node-keri and keripy agree on the wire: that AIDs, KELs, and
 * signed messages produced by one are accepted by the other, in both
 * directions.
 *
 * keripy runs in a Python child process driven by `test/interop/keripy_bridge.py`;
 * `test/interop/bridge.ts` wraps that exchange. keripy is an optional,
 * separately-provisioned dependency — run `bash test/interop/setup-keripy.sh`
 * to install it into the project-relative `./keripy` virtualenv. When it has
 * not been provisioned this whole suite is skipped.
 *
 * Wire form: a KEL is a CESR stream — each event's JSON followed by a `-A`
 * controller-signature counter and an indexed signature ("Siger"). node-keri
 * and keripy both produce and consume exactly that form, so a KEL crosses the
 * bridge as a single string with no per-event wrapper.
 *
 * Profile note: node-keri's "KERI Direct JSON Profile v1" uses SHA2-256 (CESR
 * code `I`) for both the event SAID `d` and the identifier prefix `i`, so an
 * inception event has `d == i`. keripy defaults its SAID to Blake3-256, so the
 * bridge pins keripy to SHA2-256 when generating events — see the bridge's
 * module docstring. With that pinning the two implementations are byte-exact.
 */

import { createIdentifier } from '../src/api/create-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { interactIdentifier } from '../src/api/interact-identifier';
import { verifyKel } from '../src/api/verify-kel';
import { verifySignatureWithDid } from '../src/api/verify-signature-with-did';
import { keyPairFromSeed } from '../src/crypto/keypair';
import { sign } from '../src/crypto/ed25519';
import { encodePublicKeyEd25519, encodeSignatureEd25519 } from '../src/cesr/encode';
import { parseDidKeri } from '../src/did/did-keri';
import type { Aid } from '../src/did/did-keri';
import { parseKel } from '../src/event/stream';
import { utf8Encode } from '../src/bytes/utf8';
import type { CesrSignature } from '../src/cesr/qualified';
import {
	keripyAvailable,
	keripyUnavailableReason,
	keripyGenKel,
	keripyVerifyKel,
	keripySign,
	keripyVerifySig,
} from './interop/bridge';

/**
 * keripy is provisioned separately (see the module docstring). When it is not
 * installed, run the suite through `describe.skip` so the tests are reported
 * as skipped rather than failing on a missing reference implementation.
 *
 * A skip is never silent: the reason (which interpreters were probed and how
 * each failed) is logged, so a partial/broken install — e.g. keripy installed
 * but libsodium missing — is distinguishable from "keripy not installed".
 */
const keripyReady = keripyAvailable();
if (!keripyReady) {
	console.warn(`\n[keripy interop] suite skipped:\n${keripyUnavailableReason()}\n`);
}
const describeInterop = keripyReady ? describe : describe.skip;

/**
 * The four key seeds shared by both implementations for the KEL fixtures.
 *
 * keripy's bridge derives a key from integer seed `n` as the raw bytes
 * `range(n, n + 32)`. The matching node-keri key is `keyPairFromSeed` of the
 * same 32-byte run, so `seedKeyPair(n)` and the bridge's `_signer(n)` are the
 * same key. Seeds stay within [0, 223] so `n + 31 <= 255`.
 */
const SEEDS = [0, 32, 64, 96];

/** The node-keri keypair for the bridge's integer seed `n`. */
function seedKeyPair(n: number) {
	const raw = new Uint8Array(32);
	for (let i = 0; i < 32; i++) raw[i] = n + i;
	return keyPairFromSeed(raw);
}

/** Anchor payload for the interaction event, identical on both sides. */
const ANCHOR = { kind: 'announce', ref: 'interop' };

/**
 * Build the shared four-event KEL with node-keri: inception, rotation,
 * interaction, rotation — sequence numbers 0..3. keripy's `gen-kel` builds the
 * structurally identical log from the same seeds and anchor. The KEL is the
 * four wire-form event frames concatenated into one CESR stream.
 */
function buildNodeKeriKel() {
	const [k0, k1, k2, k3] = SEEDS.map(seedKeyPair);

	const icp = createIdentifier({ currentKeyPair: k0, nextKeyPair: k1 });
	const rot1 = rotateIdentifier({
		state: icp.state,
		currentPrivateKey: k1!.privateKey,
		nextKeyPair: k2!,
	});
	const ixn = interactIdentifier({
		state: rot1.state,
		currentPrivateKey: k1!.privateKey,
		data: [ANCHOR],
	});
	const rot2 = rotateIdentifier({
		state: ixn.state,
		currentPrivateKey: k2!.privateKey,
		nextKeyPair: k3!,
	});

	const kel =
		icp.inceptionEvent
		+ rot1.rotationEvent
		+ ixn.interactionEvent
		+ rot2.rotationEvent;
	return { did: icp.did, aid: icp.aid, kel, finalState: rot2.state };
}

describeInterop('keripy interop: AIDs', () => {
	test('an AID minted by node-keri is re-derived by keripy from its KEL', () => {
		const { aid, kel } = buildNodeKeriKel();

		// keripy independently derives the prefix from the inception event it
		// is handed. Re-deriving the same AID is exactly "validating" it.
		const result = keripyVerifyKel(aid, kel);

		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.aid).toBe(aid);
		}
	});

	test('an AID minted by keripy is accepted and re-derived by node-keri', () => {
		const generated = keripyGenKel(SEEDS, ANCHOR);

		// The DID parses under node-keri's strict offline did:keri grammar...
		const parsed = parseDidKeri(generated.did);
		expect(parsed.aid).toBe(generated.aid);

		// ...and replaying keripy's KEL re-derives the very same AID.
		const result = verifyKel({ aid: parsed.aid, kel: generated.kel });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.aid).toBe(generated.aid);
		}
	});
});

describeInterop('keripy interop: KELs', () => {
	test('a node-keri KEL (icp, rot, ixn, rot) is accepted by keripy', () => {
		const { aid, kel, finalState } = buildNodeKeriKel();

		const result = keripyVerifyKel(aid, kel);

		expect(result.ok).toBe(true);
		if (result.ok) {
			// keripy replayed the whole log: digest chain, signatures, and
			// pre-rotation commitments all checked out.
			expect(result.sn).toBe(3);
			expect(result.said).toBe(finalState.lastEventDigest);
			expect(result.currentKeys).toEqual([finalState.currentPublicKey]);
		}
	});

	test('a keripy KEL (icp, rot, ixn, rot) is accepted by node-keri', () => {
		const generated = keripyGenKel(SEEDS, ANCHOR);
		const events = parseKel(generated.kel);
		expect(events).toHaveLength(4);

		const result = verifyKel({
			aid: generated.aid as unknown as Aid,
			kel: generated.kel,
		});

		expect(result.ok).toBe(true);
		if (result.ok) {
			const lastEvent = events[events.length - 1]!.event;
			expect(result.state.sequenceNumber).toBe(3);
			expect(result.state.lastEventDigest).toBe(lastEvent.d as string);
			// The final rotation revealed seed 64; that is the current key.
			expect(result.state.currentPublicKey).toBe(
				encodePublicKeyEd25519(seedKeyPair(64).publicKey.raw)
			);
		}
	});

	test('node-keri and keripy produce byte-identical signed KEL streams', () => {
		// The strongest interop statement: from the same seeds and anchor, the
		// two implementations independently produce the same CESR stream —
		// identical event bytes AND identical (deterministic Ed25519) indexed
		// signatures behind identical `-A` counters.
		const { kel } = buildNodeKeriKel();
		const generated = keripyGenKel(SEEDS, ANCHOR);

		expect(kel).toEqual(generated.kel);
	});
});

describeInterop('keripy interop: signed messages', () => {
	const message = utf8Encode('agent-to-agent payload — interop check');

	test('a message signed by node-keri verifies under keripy', () => {
		const signer = seedKeyPair(0);
		const signature = encodeSignatureEd25519(sign(signer.privateKey, message));
		const publicKey = encodePublicKeyEd25519(signer.publicKey.raw);

		expect(keripyVerifySig(publicKey, message, signature)).toBe(true);
	});

	test('keripy rejects a node-keri signature over a different payload', () => {
		// Guards the test above against being vacuously true: the same
		// signature must NOT verify against altered bytes.
		const signer = seedKeyPair(0);
		const signature = encodeSignatureEd25519(sign(signer.privateKey, message));
		const publicKey = encodePublicKeyEd25519(signer.publicKey.raw);

		const tampered = utf8Encode('agent-to-agent payload — interop check!');
		expect(keripyVerifySig(publicKey, tampered, signature)).toBe(false);
	});

	test('a message signed by keripy verifies under node-keri', () => {
		// node-keri's identifier whose current (and only) key is seed 0 — the
		// same key keripy signs with below.
		const id = createIdentifier({
			currentKeyPair: seedKeyPair(0),
			nextKeyPair: seedKeyPair(32),
		});

		const signed = keripySign(0, message);
		// keripy signed with the key node-keri's KEL makes authoritative.
		expect(signed.publicKey).toBe(
			encodePublicKeyEd25519(seedKeyPair(0).publicKey.raw)
		);

		const ok = verifySignatureWithDid({
			did: id.did,
			kel: id.inceptionEvent,
			payload: message,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(true);
	});

	test('node-keri rejects a keripy signature over a different payload', () => {
		const id = createIdentifier({
			currentKeyPair: seedKeyPair(0),
			nextKeyPair: seedKeyPair(32),
		});
		const signed = keripySign(0, message);

		const tampered = utf8Encode('a different payload');
		const ok = verifySignatureWithDid({
			did: id.did,
			kel: id.inceptionEvent,
			payload: tampered,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(false);
	});
});
