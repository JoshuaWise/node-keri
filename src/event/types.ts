/**
 * KERI event data model for the Direct JSON Profile v1.
 *
 * The shapes here are the *on-the-wire* representation: every field is
 * present in the JSON, in the exact form it would be canonicalized for
 * digesting and signing. Optional or excluded KERI features (multisig,
 * witnesses, delegation, configuration traits) are pinned to their empty
 * sentinel values so that the profile boundary is enforced by the type
 * system as well as by runtime validators.
 */

import { CesrDigest, CesrIndexedSignature, CesrPublicKey } from '../cesr/qualified';
import { Aid } from '../did/did-keri';

/**
 * Three event types are supported:
 *   - `icp` inception: establishes the AID and initial signing/next keys.
 *   - `rot` rotation: rolls signing key forward by revealing the prior
 *     next-key and committing a fresh next-key.
 *   - `ixn` interaction: anchors arbitrary data without rotating keys.
 */
export type KeriEventType = 'icp' | 'rot' | 'ixn';

/**
 * Fields shared by every event in the KEL.
 *
 * `d` is the self-addressing digest of the event (computed with `d` itself,
 * and `i` for a transferable inception, replaced by a fixed-length
 * placeholder).
 * `i` is the AID of the controller; for a transferable inception it equals
 * `d`, while for a non-transferable inception it is the controller's
 * (`B`-coded) Ed25519 key itself.
 * `s` is the sequence number as lowercase hex without leading zeros.
 * `v` is the KERI version string `KERI10JSON{size:06x}_` where `size` is the
 *   serialized byte length of the event in lowercase hex.
 */
export interface KeriEventBase {
	v: string;
	t: KeriEventType;
	d: CesrDigest;
	i: Aid;
	s: string;
}

export interface InceptionEvent extends KeriEventBase {
	t: 'icp';
	kt: '1';
	k: readonly [CesrPublicKey];
	nt: '1';
	n: readonly [CesrDigest];
	bt: '0';
	b: readonly [];
	c: readonly [];
	a: readonly [];
}

/**
 * Inception of a *non-transferable* identifier.
 *
 * A non-transferable AID is a basic prefix: `i` is the controller's
 * non-transferable (`B`-coded) Ed25519 key itself, not a self-addressing
 * digest. The event commits to no next key — `nt` is `"0"` and `n` is empty —
 * so the identifier can never rotate, and its KEL is exactly this one event.
 *
 * node-keri *verifies* these (a keripy non-transferable AID is the motivating
 * case) but does not generate them: no constructor emits one.
 */
export interface NonTransferableInceptionEvent extends KeriEventBase {
	t: 'icp';
	kt: '1';
	k: readonly [CesrPublicKey];
	nt: '0';
	n: readonly [];
	bt: '0';
	b: readonly [];
	c: readonly [];
	a: readonly [];
}

export interface RotationEvent extends KeriEventBase {
	t: 'rot';
	p: CesrDigest;
	kt: '1';
	k: readonly [CesrPublicKey];
	nt: '1';
	n: readonly [CesrDigest];
	bt: '0';
	br: readonly [];
	ba: readonly [];
	a: readonly [];
}

export interface InteractionEvent extends KeriEventBase {
	t: 'ixn';
	p: CesrDigest;
	a: readonly unknown[];
}

export type KeriEvent =
	| InceptionEvent
	| NonTransferableInceptionEvent
	| RotationEvent
	| InteractionEvent;

/**
 * An event paired with the signature(s) authorizing it.
 *
 * The signature is a CESR *indexed* signature (a "Siger", code `A`): its qb64
 * form embeds the index of the signing key within the establishment event's
 * key list. This profile is single-controller, threshold 1, so there is
 * exactly one signature and its index is always 0.
 *
 * `SignedKeriEvent` is the in-memory shape of an event. Its wire form is the
 * CESR stream frame produced by `encodeEventFrame` — that, not this object, is
 * what the high-level API and KEL transport use.
 */
export interface SignedKeriEvent {
	event: KeriEvent;
	signatures: readonly [CesrIndexedSignature];
}
