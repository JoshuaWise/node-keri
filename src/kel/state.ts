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

export interface KeriState {
	readonly aid: Aid;
	readonly did: DidKeri;
	/** Sequence number of the most-recently applied event. Inception is 0. */
	readonly sequenceNumber: number;
	/** SAID of the most-recently applied event; the next event's `p`. */
	readonly lastEventDigest: CesrDigest;
	/** Currently authoritative signing key, qb64-encoded. */
	readonly currentPublicKey: CesrPublicKey;
	/** Pre-rotated commitment that the next rotation must reveal a key for. */
	readonly nextKeyCommitment: CesrDigest;
	/** Always true in this profile — non-transferable AIDs are out of scope. */
	readonly transferable: true;
	/** Type of the most-recently applied event. */
	readonly eventType: KeriEventType;
}
