import { utf8Encode } from '../bytes/utf8';
import { CanonicalJsonError } from '../profile/errors';

/**
 * Serialize `value` to a deterministic UTF-8 byte sequence suitable for
 * digesting and signing.
 *
 * Rules:
 *   - Object keys are emitted in the object's own property order (insertion
 *     order for string keys), never sorted. KERI serializes event fields in a
 *     fixed canonical order rather than alphabetically, so a caller that needs
 *     a canonically-ordered event must build it that way — see
 *     `toCanonicalEvent` in `field-order.ts`. Values nested inside an event
 *     (interaction anchors) are likewise emitted in insertion order.
 *   - No insignificant whitespace is emitted.
 *   - Numbers must be finite. `NaN`, `Infinity`, `-Infinity`, and `-0`
 *     are rejected because their JSON representations are either invalid
 *     or implementation-defined.
 *   - Number serialization is whatever `JSON.stringify` produces, so it is
 *     only *deterministic* — and therefore only safe to digest — for integers
 *     within the safe-integer range. A number outside that range, or a
 *     non-canonical numeric literal on the wire (`1e3`, `1.0`, leading-zero
 *     forms), does not round-trip to the same bytes a producer emitted, so an
 *     event carrying one fails replay as `NON_CANONICAL_EVENT`. Anchored
 *     application data (an interaction event's `a`) should therefore confine
 *     numbers to safe integers, or carry larger/fractional values as strings.
 *   - `undefined`, functions, symbols, and BigInt are rejected at every
 *     position (including object values, where `JSON.stringify` would
 *     normally drop them silently).
 *   - Arrays preserve insertion order.
 *   - String escaping follows `JSON.stringify`, which is well-specified.
 */
export function canonicalizeJson(value: unknown): Uint8Array {
	return utf8Encode(canonicalize(value));
}

function canonicalize(value: unknown): string {
	if (value === null) return 'null';

	const type = typeof value;

	if (type === 'boolean') return value ? 'true' : 'false';

	if (type === 'string') return JSON.stringify(value);

	if (type === 'number') {
		const n = value as number;
		if (!Number.isFinite(n)) {
			throw new CanonicalJsonError(`non-finite number: ${String(n)}`);
		}
		if (Object.is(n, -0)) {
			throw new CanonicalJsonError('negative zero is not allowed');
		}
		return JSON.stringify(n);
	}

	if (type === 'bigint') {
		throw new CanonicalJsonError('bigint is not JSON-representable');
	}

	if (type === 'undefined') {
		throw new CanonicalJsonError('undefined is not allowed');
	}

	if (type === 'function' || type === 'symbol') {
		throw new CanonicalJsonError(`${type} is not allowed`);
	}

	if (Array.isArray(value)) {
		const parts: string[] = [];
		for (const v of value) parts.push(canonicalize(v));
		return '[' + parts.join(',') + ']';
	}

	if (type === 'object') {
		// Refuse anything that isn't a plain object. Class instances,
		// Maps, Sets, etc. have no canonical JSON form.
		const proto = Object.getPrototypeOf(value);
		if (proto !== null && proto !== Object.prototype) {
			throw new CanonicalJsonError('only plain objects are supported');
		}
		const obj = value as Record<string, unknown>;
		const keys = Object.keys(obj);
		const parts: string[] = [];
		for (const k of keys) {
			const v = obj[k];
			parts.push(JSON.stringify(k) + ':' + canonicalize(v));
		}
		return '{' + parts.join(',') + '}';
	}

	throw new CanonicalJsonError(`unsupported value type: ${type}`);
}
