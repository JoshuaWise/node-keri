/**
 * Replay-derived state of an identifier's KEL.
 *
 * `KeriState` summarizes everything a verifier needs to reason about the
 * latest authoritative key material for a given AID. It is *not* a generic
 * "user-supplied" object: only `verifyKel` (Milestone 4) and the event
 * constructors in this milestone may produce one. Functions that consume a
 * state should treat it as trusted within the calling process and do not
 * re-validate signatures against it.
 */

import { CesrDigest, CesrPublicKey } from '../cesr/qualified';
import { Aid, DidKeri } from '../did/did-keri';
import { KeriEventType } from '../event/types';

/** State fields every identifier has, whether or not it has a KEL. */
interface KeriStateBase {
	readonly aid: Aid;
	readonly did: DidKeri;
	/**
	 * Sequence number of the most-recently applied event. Inception is 0; also
	 * 0 for a bare non-transferable AID resolved with no events at all.
	 */
	readonly sequenceNumber: number;
	/** Currently authoritative signing key, qb64-encoded. */
	readonly currentPublicKey: CesrPublicKey;
}

/**
 * Replay state of a transferable identifier. It always has a KEL, so it
 * carries event-derived fields, and it pre-rotates, so it carries the
 * commitment the next rotation must reveal a key for.
 */
export interface TransferableKeriState extends KeriStateBase {
	readonly transferable: true;
	/**
	 * Never `true` for a transferable state — a live identifier is not
	 * deactivated. Declared so `deactivated` is a field of every `KeriState`
	 * and can be read without first narrowing the union.
	 */
	readonly deactivated?: false;
	/** SAID of the most-recently applied event; the next event's `p`. */
	readonly lastEventDigest: CesrDigest;
	/** Pre-rotated commitment that the next rotation must reveal a key for. */
	readonly nextKeyCommitment: CesrDigest;
	/** Type of the most-recently applied event. */
	readonly eventType: KeriEventType;
}

/**
 * State of a non-transferable identifier. It commits to no next key and can
 * never rotate, so there is no `nextKeyCommitment`. A non-transferable AID may
 * be backed by a trivial single-event KEL or by nothing at all — it is
 * self-certifying either way — so the event-derived fields are present only
 * when it was verified from a KEL. node-keri verifies these but never
 * generates them.
 */
export interface NonTransferableKeriState extends KeriStateBase {
	readonly transferable: false;
	/**
	 * Never `true` for a non-transferable basic prefix: it was never extensible
	 * in the first place, so "deactivated" does not apply. Declared so
	 * `deactivated` is a field of every `KeriState`.
	 */
	readonly deactivated?: false;
	/**
	 * SAID of the inception event — present when this AID was verified from a
	 * (trivial, single-event) KEL, absent for a bare non-transferable AID
	 * resolved with no KEL at all.
	 */
	readonly lastEventDigest?: CesrDigest;
	/** `'icp'` when verified from a KEL; absent for a bare AID with no KEL. */
	readonly eventType?: KeriEventType;
}

/**
 * State of a *deactivated* identifier — a transferable AID that was abandoned
 * by a deactivation event (a rotation committing to no next key). Like a
 * non-transferable identifier it can never extend its KEL again, so it is not
 * `transferable`; unlike one, it was minted as a self-addressing AID and has a
 * real multi-event KEL behind it. `deactivated` is `true` to tell the two
 * apart. There is no `nextKeyCommitment`: the identifier committed to nothing.
 */
export interface DeactivatedKeriState extends KeriStateBase {
	readonly transferable: false;
	readonly deactivated: true;
	/** SAID of the deactivation event — the final event of the KEL. */
	readonly lastEventDigest: CesrDigest;
	/** Always `'rot'`: a deactivation is a rotation event. */
	readonly eventType: 'rot';
}

/**
 * Replay-derived state of an identifier — a discriminated union on
 * `transferable`. Narrow on that field to reach `nextKeyCommitment` (and the
 * always-present `lastEventDigest` / `eventType`), which exist only for a
 * transferable identifier. The two `transferable: false` members — a bare
 * non-transferable basic prefix and a deactivated identifier — are told apart
 * by `deactivated`, which is readable on any `KeriState`.
 */
export type KeriState =
	| TransferableKeriState
	| NonTransferableKeriState
	| DeactivatedKeriState;
