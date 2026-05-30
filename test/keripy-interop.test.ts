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
 *
 * Non-transferable AIDs: node-keri generates and verifies both forms. The
 * suite below checks that a non-transferable AID minted by keripy — a basic
 * prefix whose `i` is the controller's `B`-coded key, with a single-event KEL
 * and no rotation — is ingested and verified by node-keri, and the mirror: that
 * node-keri's `createNonTransferableIdentifier` mints the byte-exact same
 * `B`-coded AID keripy derives for a given key.
 *
 * Deactivated AIDs: deactivation — a rotation to no next key — is generated
 * and verified by both implementations, so the last suite exercises it in
 * both directions, including a byte-exact check. Crucially it also proves the
 * abandonment is terminal *each way*: an event appended after the deactivation
 * is rejected by node-keri (`DEACTIVATED_NOT_EXTENSIBLE`) and refused by
 * keripy (its `Kever` reports the prefix abandoned and the KEL does not grow).
 */

import { createIdentifier } from '../src/api/create-identifier';
import { createNonTransferableIdentifier } from '../src/api/create-non-transferable-identifier';
import { rotateIdentifier } from '../src/api/rotate-identifier';
import { interactOnIdentifier } from '../src/api/interact-on-identifier';
import { deactivateIdentifier } from '../src/api/deactivate-identifier';
import { verifyIdentifier } from '../src/api/verify-identifier';
import { verifySignatureWithDid } from '../src/did/verify-signature-with-did';
import { verifyDid } from '../src/did/verify-did';
import { createDidDocument } from '../src/did/document';
import { keyPairFromSeed, publicKeyToCesr, rawPublicKey } from '../src/crypto/keypair';
import { sign } from '../src/crypto/ed25519';
import {
	encodeNonTransferablePublicKeyEd25519,
	encodeSignatureEd25519,
} from '../src/cesr/encode';
import { parseDidKeri } from '../src/did/did-keri';
import type { Aid, DidKeri } from '../src/did/did-keri';
import { createInteractionEvent } from '../src/event/interaction';
import {
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
} from '../src/event/digest';
import { encodeEventFrame, parseKel } from '../src/event/stream';
import type { KeriEvent, SignedKeriEvent } from '../src/event/types';
import { utf8Encode } from '../src/bytes/utf8';
import type { CesrSignature } from '../src/cesr/qualified';
import type { TransferableKeriState } from '../src/kel/state';
import {
	keripyAvailable,
	keripyUnavailableReason,
	keripyGenKel,
	keripyGenNonTransferableKel,
	keripyGenDeactivatedKel,
	keripyVerifyKel,
	keripyVerifyExtension,
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

	const icp = createIdentifier({
		currentPrivateKey: k0!.privateKey,
		nextPublicKey: k1!.publicKey,
	});
	const rot1 = rotateIdentifier({
		state: icp.state,
		newPrivateKey: k1!.privateKey,
		nextPublicKey: k2!.publicKey,
	});
	const ixn = interactOnIdentifier({
		state: rot1.state,
		currentPrivateKey: k1!.privateKey,
		data: [ANCHOR],
	});
	const rot2 = rotateIdentifier({
		state: ixn.state,
		newPrivateKey: k2!.privateKey,
		nextPublicKey: k3!.publicKey,
	});

	const kel = icp.event + rot1.event + ixn.event + rot2.event;
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
		const result = verifyIdentifier({ aid: parsed.aid, kel: generated.kel });
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

		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel: generated.kel,
		});

		expect(result.ok).toBe(true);
		if (result.ok) {
			const lastEvent = events[events.length - 1]!.event;
			expect(result.state.lastSequenceNumber).toBe(3);
			expect(result.state.lastEventDigest).toBe(lastEvent.d as string);
			// The final rotation revealed seed 64; that is the current key.
			expect(result.state.deactivated).toBe(false);
			if (!result.state.deactivated) {
				expect(result.state.currentPublicKey).toBe(
					publicKeyToCesr(seedKeyPair(64).publicKey)
				);
			}
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
		const publicKey = publicKeyToCesr(signer.publicKey);

		expect(keripyVerifySig(publicKey, message, signature)).toBe(true);
	});

	test('keripy rejects a node-keri signature over a different payload', () => {
		// Guards the test above against being vacuously true: the same
		// signature must NOT verify against altered bytes.
		const signer = seedKeyPair(0);
		const signature = encodeSignatureEd25519(sign(signer.privateKey, message));
		const publicKey = publicKeyToCesr(signer.publicKey);

		const tampered = utf8Encode('agent-to-agent payload — interop check!');
		expect(keripyVerifySig(publicKey, tampered, signature)).toBe(false);
	});

	test('a message signed by keripy verifies under node-keri', () => {
		// node-keri's identifier whose current (and only) key is seed 0 — the
		// same key keripy signs with below.
		const id = createIdentifier({
			currentPrivateKey: seedKeyPair(0).privateKey,
			nextPublicKey: seedKeyPair(32).publicKey,
		});

		const signed = keripySign(0, message);
		// keripy signed with the key node-keri's KEL makes authoritative.
		expect(signed.publicKey).toBe(publicKeyToCesr(seedKeyPair(0).publicKey));

		const ok = verifySignatureWithDid({
			did: id.did,
			kel: id.event,
			payload: message,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(true);
	});

	test('node-keri rejects a keripy signature over a different payload', () => {
		const id = createIdentifier({
			currentPrivateKey: seedKeyPair(0).privateKey,
			nextPublicKey: seedKeyPair(32).publicKey,
		});
		const signed = keripySign(0, message);

		const tampered = utf8Encode('a different payload');
		const ok = verifySignatureWithDid({
			did: id.did,
			kel: id.event,
			payload: tampered,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(false);
	});
});

/**
 * Re-frame a keripy non-transferable inception after mutating one field, so a
 * test can assert node-keri rejects a *specific* malformation of an otherwise
 * genuine keripy event. `mutate` edits a copy of the parsed inception in place;
 * the SAID `d` and version `v` are then recomputed under SHA-256 (the digest
 * the bridge pins, and node-keri's default), so the frame is well-formed and
 * self-consistent and the injected defect is the only thing wrong with it.
 *
 * keripy's original indexed signature is reused verbatim: every fixture here is
 * rejected at shape or AID-derivation, both of which run before the signature
 * is ever checked, so a cryptographically-correct signature is unnecessary (a
 * structurally valid Siger is all `encodeEventFrame` requires). The result is
 * the single-frame CESR stream node-keri's verifier ingests.
 */
function reframeKeripyNonTransferableIcp(
	base: SignedKeriEvent,
	mutate: (event: Record<string, unknown>) => void
): string {
	const event: Record<string, unknown> = { ...base.event };
	mutate(event);
	// `i` is the controller's `B` key, kept verbatim — only `d` is
	// self-addressing for a basic prefix — so it is a fixed input to the digest,
	// exactly as node-keri's replay verifier recomputes it.
	const { said, versionString } = computeEventSaid({
		t: 'icp',
		d: SAID_PLACEHOLDER,
		i: event.i,
		s: event.s,
		kt: event.kt,
		k: event.k,
		nt: event.nt,
		n: event.n,
		bt: event.bt,
		b: event.b,
		c: event.c,
		a: event.a,
	});
	event.v = versionString;
	event.d = said;
	return encodeEventFrame({
		event: event as unknown as KeriEvent,
		signatures: base.signatures,
	});
}

/**
 * Non-transferable AIDs are the one case node-keri verifies but does not
 * generate (see the module docstring). keripy mints a non-transferable AID —
 * a basic prefix that is the controller's `B`-coded Ed25519 key, with a
 * single-event KEL that commits to no next key — and these tests prove
 * node-keri ingests, verifies, and resolves it.
 */
describeInterop('keripy interop: non-transferable AIDs', () => {
	/** Seed for the non-transferable identifier — within [0, 223] as always. */
	const NT_SEED = 0;

	test('a non-transferable AID minted by keripy is verified by node-keri', () => {
		const generated = keripyGenNonTransferableKel(NT_SEED);

		// The DID parses under node-keri's strict offline grammar: a
		// non-transferable AID is a `B`-coded key, not a digest.
		const parsed = parseDidKeri(generated.did);
		expect(parsed.aid).toBe(generated.aid);

		// Its single-event KEL replays and re-derives the same AID.
		const result = verifyIdentifier({ aid: parsed.aid, kel: generated.kel });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.transferable).toBe(false);
			expect(result.state.aid).toBe(generated.aid);
			expect(result.state.lastSequenceNumber).toBe(0);
			expect(result.state.deactivated).toBe(false);
			if (!result.state.deactivated) {
				// A non-transferable AID is a basic prefix: it *is* its own
				// controller key, so the current key equals the AID itself.
				expect(result.state.currentPublicKey).toBe(generated.aid);
			}
		}
	});

	test('node-keri mints the same non-transferable AID as keripy for a given key', () => {
		// Generation parity, the mirror of the verification test above: minting
		// from the same key must produce the byte-exact `B`-coded AID/DID keripy
		// derives. `seedKeyPair(NT_SEED)` and the bridge's signer share the seed.
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const minted = createNonTransferableIdentifier({
			publicKey: seedKeyPair(NT_SEED).publicKey,
		});
		expect(minted.aid).toBe(generated.aid);
		expect(minted.did).toBe(generated.did);
	});

	test('node-keri rejects a non-transferable KEL replayed under the wrong AID', () => {
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const other = keripyGenNonTransferableKel(NT_SEED + 32);

		// A structurally valid non-transferable KEL still fails when it does
		// not derive the AID the caller asked for.
		const result = verifyIdentifier({
			aid: other.aid as unknown as Aid,
			kel: generated.kel,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('INVALID_DID');
		}
	});

	test('node-keri rejects a rotation appended to a non-transferable KEL', () => {
		const generated = keripyGenNonTransferableKel(NT_SEED);

		// Borrow a well-formed rotation frame from a transferable keripy KEL
		// and append it. A non-transferable identifier commits to no next key,
		// so the verifier rejects the extra event before even inspecting it.
		const rotationFrame = encodeEventFrame(parseKel(keripyGenKel(SEEDS).kel)[1]!);
		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel: generated.kel + rotationFrame,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('NON_TRANSFERABLE_NOT_EXTENSIBLE');
		}
	});

	test('a message signed by a keripy non-transferable key verifies under node-keri', () => {
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const payload = utf8Encode('non-transferable agent payload — interop');

		// keripy signs `payload` with seed NT_SEED. The raw Ed25519 signature
		// does not depend on the transferable flag, so this is the very key
		// the non-transferable KEL makes authoritative.
		const signed = keripySign(NT_SEED, payload);
		const ok = verifySignatureWithDid({
			did: generated.did as DidKeri,
			kel: generated.kel,
			payload,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(true);

		// Guard against vacuity: the same signature must not verify altered bytes.
		const tampered = verifySignatureWithDid({
			did: generated.did as DidKeri,
			kel: generated.kel,
			payload: utf8Encode('non-transferable agent payload — interop!'),
			signature: signed.signature as CesrSignature,
		});
		expect(tampered).toBe(false);
	});

	test('a keripy non-transferable signature verifies with no KEL at all', () => {
		// The canonical non-transferable case: only the DID is exchanged, no
		// KEL — the `B`-coded AID is itself the signing key. node-keri reads
		// the key straight from the prefix; `''` is the "no KEL" value.
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const payload = utf8Encode('bare non-transferable prefix — interop');
		const signed = keripySign(NT_SEED, payload);

		const ok = verifySignatureWithDid({
			did: generated.did as DidKeri,
			kel: '',
			payload,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(true);

		const tampered = verifySignatureWithDid({
			did: generated.did as DidKeri,
			kel: '',
			payload: utf8Encode('bare non-transferable prefix — interop!'),
			signature: signed.signature as CesrSignature,
		});
		expect(tampered).toBe(false);
	});

	test('node-keri resolves a keripy non-transferable DID with no KEL', () => {
		// `verifyDid` with the empty-string "no KEL" value: the state is
		// projected straight from the self-certifying `B` prefix.
		const generated = keripyGenNonTransferableKel(NT_SEED);

		const result = verifyDid({ did: generated.did as DidKeri, kel: '' });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.transferable).toBe(false);
			expect(result.state.aid).toBe(generated.aid);
			// Resolved bare from the prefix: no event-derived fields.
			expect(result.state.lastEventDigest).toBeUndefined();
			const doc = createDidDocument({ state: result.state });
			expect(doc.id).toBe(generated.did);
			// The sole verification method is the AID itself, as a JWK.
			expect(doc.verificationMethod).toHaveLength(1);
		}
	});

	test('node-keri resolves a keripy non-transferable DID from its KEL', () => {
		// The same AID also resolves the KEL way — replaying its trivial
		// single-event log — and yields an equivalent document.
		const generated = keripyGenNonTransferableKel(NT_SEED);

		const result = verifyDid({
			did: generated.did as DidKeri,
			kel: generated.kel,
		});
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.transferable).toBe(false);
			expect(result.state.aid).toBe(generated.aid);
			// Verified from its single-event KEL: event-derived fields are present,
			// which is what distinguishes this from the bare resolution above.
			expect(result.state.lastEventDigest).toBeDefined();
			expect(result.state.lastEventType).toBe('icp');
			expect(createDidDocument({ state: result.state }).id).toBe(generated.did);
		}
	});

	// The three tests below take a genuine keripy non-transferable inception and
	// mutate exactly one thing about it — re-deriving the SAID/version so the
	// only defect is the injected one — to prove node-keri's shape and
	// derivation guards fire on near-real events, not just on hand-rolled junk.

	test('node-keri rejects a non-transferable inception carrying the EO trait', () => {
		// `EO` ("establishment only") is meaningful only for an extensible
		// (transferable) KEL; on a one-event basic prefix it is redundant, so the
		// profile refuses it rather than silently accepting a no-op trait.
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const icp = parseKel(generated.kel)[0]!;
		const kel = reframeKeripyNonTransferableIcp(icp, (e) => {
			e.c = ['EO'];
		});

		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
			if (result.error.code === 'UNSUPPORTED_FEATURE') {
				expect(result.error.feature).toMatch(/EO is not supported/);
			}
		}
	});

	test('node-keri rejects a non-transferable inception that commits to a next key', () => {
		// A basic prefix commits to no next key (`nt:"0"`, `n:[]`) — that is what
		// makes it non-transferable. Splice in a real pre-rotation commitment and
		// the shape pass rejects it: a key the identifier could never rotate to.
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const icp = parseKel(generated.kel)[0]!;
		const kel = reframeKeripyNonTransferableIcp(icp, (e) => {
			e.nt = '1';
			e.n = [deriveNextKeyCommitment(seedKeyPair(64).publicKey)];
		});

		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('UNSUPPORTED_FEATURE');
			if (result.error.code === 'UNSUPPORTED_FEATURE') {
				expect(result.error.feature).toMatch(/next-key threshold/);
			}
		}
	});

	test('node-keri rejects a non-transferable inception whose `i` is not its signing key', () => {
		// For a basic prefix the AID *is* the controlling key, so `i` must equal
		// the single entry of `k`. Repoint `k[0]` at a different `B` key (with a
		// valid recomputed SAID) and node-keri rejects the internal inconsistency
		// — distinct from the wrong-AID case, which is asserted separately above.
		const generated = keripyGenNonTransferableKel(NT_SEED);
		const icp = parseKel(generated.kel)[0]!;
		const otherKey = encodeNonTransferablePublicKeyEd25519(
			rawPublicKey(seedKeyPair(32).publicKey)
		);
		const kel = reframeKeripyNonTransferableIcp(icp, (e) => {
			e.k = [otherKey];
		});

		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('INVALID_DID');
			if (result.error.code === 'INVALID_DID') {
				expect(result.error.message).toMatch(/not the controller signing key/);
			}
		}
	});
});

/**
 * Deactivation seeds: the inception key and the pre-rotated key the
 * deactivation event reveals. Two is all a deactivated KEL needs — inception
 * plus the deactivation rotation.
 */
const DEACT_SEEDS = [0, 32];

/**
 * Build the shared deactivated KEL with node-keri: an inception followed by a
 * deactivation event (a rotation to no next key). keripy's `gen-deactivated-kel`
 * builds the structurally identical — and byte-identical — log from the same
 * seeds.
 */
function buildNodeKeriDeactivatedKel() {
	const [k0, k1] = DEACT_SEEDS.map(seedKeyPair);
	const id = createIdentifier({
		currentPrivateKey: k0!.privateKey,
		nextPublicKey: k1!.publicKey,
	});
	const deact = deactivateIdentifier({
		state: id.state,
		newPrivateKey: k1!.privateKey,
	});
	return {
		did: id.did,
		aid: id.aid,
		kel: id.event + deact.event,
		state: deact.state,
	};
}

/**
 * Forge a well-formed, correctly-signed interaction event chained onto the
 * last event of `kel`. `createInteractionEvent` is fed a state that *looks*
 * transferable so it produces a genuine frame — a hostile relay could do
 * exactly this. Replaying it (under node-keri or keripy) must still reject it
 * when the KEL it extends ends in a deactivation.
 *
 * `signerKeyPair` must be the key the deactivation event revealed — that is
 * the deactivated identifier's current key, so the forged event is signed by
 * the key a naive verifier would otherwise accept.
 */
function forgePostDeactivationEvent(
	kel: string,
	aid: Aid,
	did: DidKeri,
	signerKeyPair: ReturnType<typeof seedKeyPair>
): string {
	const events = parseKel(kel);
	const last = events[events.length - 1]!.event;
	const pretendState: TransferableKeriState = {
		aid,
		did,
		lastSequenceNumber: Number.parseInt(last.s, 16),
		lastEventType: 'rot',
		lastEventDigest: last.d,
		currentPublicKey: publicKeyToCesr(signerKeyPair.publicKey),
		// Any commitment will do — the event never gets far enough to be
		// checked against it; replay rejects it for extending a closed KEL.
		nextKeyCommitment: deriveNextKeyCommitment(seedKeyPair(64).publicKey),
		transferable: true,
		deactivated: false,
		establishmentOnly: false,
	};
	return createInteractionEvent({
		state: pretendState,
		currentKeyPair: signerKeyPair,
		data: [],
	}).event;
}

/**
 * Deactivation — a rotation to zero next keys — is generated and verified by
 * both implementations. These tests cross it both ways, byte-exact, and prove
 * the abandonment is terminal on each side: no event survives being appended
 * to a deactivated KEL.
 */
describeInterop('keripy interop: deactivated AIDs', () => {
	test('a deactivated KEL minted by node-keri is accepted by keripy', () => {
		const { aid, kel, state } = buildNodeKeriDeactivatedKel();

		const result = keripyVerifyKel(aid, kel);

		expect(result.ok).toBe(true);
		if (result.ok) {
			// keripy replayed inception + deactivation and stopped at sn 1.
			expect(result.sn).toBe(1);
			expect(result.said).toBe(state.lastEventDigest);
			expect(state.deactivated).toBe(true);
			expect('currentPublicKey' in state).toBe(false);
		}
	});

	test('a deactivated KEL minted by keripy is verified by node-keri', () => {
		const generated = keripyGenDeactivatedKel(DEACT_SEEDS);

		const parsed = parseDidKeri(generated.did);
		expect(parsed.aid).toBe(generated.aid);

		const result = verifyIdentifier({ aid: parsed.aid, kel: generated.kel });
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.state.deactivated).toBe(true);
			expect(result.state.transferable).toBe(false);
			expect(result.state.lastEventType).toBe('rot');
			expect(result.state.lastSequenceNumber).toBe(1);
			expect(result.state.aid).toBe(generated.aid);
		}
	});

	test('node-keri and keripy produce byte-identical deactivated KEL streams', () => {
		// As with the icp/rot/ixn/rot KEL: from the same seeds the two
		// implementations independently emit the same CESR stream, the
		// deactivation event and its indexed signature included.
		const { kel } = buildNodeKeriDeactivatedKel();
		const generated = keripyGenDeactivatedKel(DEACT_SEEDS);

		expect(kel).toEqual(generated.kel);
	});

	test('node-keri rejects an event appended to a keripy deactivated KEL', () => {
		const generated = keripyGenDeactivatedKel(DEACT_SEEDS);
		// Seed 32 is the key keripy's deactivation event revealed.
		const extension = forgePostDeactivationEvent(
			generated.kel,
			generated.aid as unknown as Aid,
			generated.did as DidKeri,
			seedKeyPair(32)
		);

		const result = verifyIdentifier({
			aid: generated.aid as unknown as Aid,
			kel: generated.kel + extension,
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('DEACTIVATED_NOT_EXTENSIBLE');
		}
	});

	test('keripy rejects an event appended to a node-keri deactivated KEL', () => {
		const { aid, did, kel } = buildNodeKeriDeactivatedKel();
		// Seed 32 is the key node-keri's deactivation event revealed.
		const extension = forgePostDeactivationEvent(kel, aid, did, seedKeyPair(32));

		const result = keripyVerifyExtension(aid, kel, extension);

		expect(result.ok).toBe(true);
		if (result.ok) {
			// keripy committed inception + deactivation (sn 0, 1) and refused
			// to advance past the deactivation — the KEL did not grow.
			expect(result.rejected).toBe(true);
			expect(result.snBefore).toBe(1);
			expect(result.snAfter).toBe(1);
		}
	});

	test('node-keri will not verify a signature for a keripy-deactivated DID', () => {
		const generated = keripyGenDeactivatedKel(DEACT_SEEDS);
		const payload = utf8Encode('message from a deactivated identity — interop');

		// keripy signs with seed 32 — the key the deactivation event revealed,
		// the last key the identifier ever had. It must still not verify: the
		// DID is abandoned, so node-keri trusts no key for it.
		const signed = keripySign(32, payload);
		const ok = verifySignatureWithDid({
			did: generated.did as DidKeri,
			kel: generated.kel,
			payload,
			signature: signed.signature as CesrSignature,
		});
		expect(ok).toBe(false);
	});
});
