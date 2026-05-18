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
	 * SAID of the inception event — present when this AID was verified from a
	 * (trivial, single-event) KEL, absent for a bare non-transferable AID
	 * resolved with no KEL at all.
	 */
	readonly lastEventDigest?: CesrDigest;
	/** `'icp'` when verified from a KEL; absent for a bare AID with no KEL. */
	readonly eventType?: KeriEventType;
}

/**
 * Replay-derived state of an identifier — a discriminated union on
 * `transferable`. Narrow on that field to reach `nextKeyCommitment` (and the
 * always-present `lastEventDigest` / `eventType`), which exist only for a
 * transferable identifier.
 */
export type KeriState = TransferableKeriState | NonTransferableKeriState;
