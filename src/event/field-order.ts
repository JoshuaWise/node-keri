/**
 * KERI canonical event field order.
 *
 * KERI serializes an event — for digesting and signing — with its fields in a
 * fixed, type-specific order, not sorted alphabetically. The self-addressing
 * digest and the signature are both computed over those ordered bytes, so the
 * field order is part of the contract: a verifier that re-serializes the same
 * event with a different field order computes a different digest and a
 * different signature input.
 *
 * `toCanonicalEvent` rebuilds an event object with its top-level fields in the
 * canonical order for its type. Routing every serialization through it means
 * the bytes never depend on the order in which an event object happened to be
 * constructed in code or parsed from JSON.
 */

import { KeriEventType } from './types';
import { InvalidArgumentError } from '../profile/errors';

/**
 * The canonical field order for each event type, `v` first. This matches the
 * field ordering of the KERI key event spec for `icp` / `rot` / `ixn`.
 */
export const CANONICAL_FIELD_ORDER: Readonly<Record<KeriEventType, readonly string[]>> = {
	icp: ['v', 't', 'd', 'i', 's', 'kt', 'k', 'nt', 'n', 'bt', 'b', 'c', 'a'],
	rot: ['v', 't', 'd', 'i', 's', 'p', 'kt', 'k', 'nt', 'n', 'bt', 'br', 'ba', 'a'],
	ixn: ['v', 't', 'd', 'i', 's', 'p', 'a'],
};

/**
 * Return a new object holding `event`'s entries in KERI canonical order for
 * the event type named by its `t` field.
 *
 * Only fields that are actually present are copied — an absent field is
 * skipped, never emitted as an `undefined` value — so the helper works equally
 * on a complete event and on the digest-time partial that omits `v`.
 *
 * Throws `InvalidArgumentError` when `t` is not one of the three supported
 * event types: a serializer with no defined field order cannot proceed.
 */
export function toCanonicalEvent(event: object): Record<string, unknown> {
	const fields = event as Record<string, unknown>;
	const t = fields.t;
	const order =
		typeof t === 'string' ? CANONICAL_FIELD_ORDER[t as KeriEventType] : undefined;
	if (!order) {
		throw new InvalidArgumentError(
			`cannot serialize an event of unknown type: ${
				typeof t === 'string' ? `'${t}'` : typeof t
			}`
		);
	}
	const ordered: Record<string, unknown> = {};
	for (const key of order) {
		if (Object.hasOwn(fields, key)) {
			ordered[key] = fields[key];
		}
	}
	return ordered;
}
