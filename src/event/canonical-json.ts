import { utf8Encode } from '../bytes/utf8';
import { CanonicalJsonError } from '../profile/errors';

/**
 * Serialize `value` to a deterministic UTF-8 byte sequence suitable for
 * digesting and signing.
 *
 * Rules:
 *   - Object keys are sorted by JavaScript string comparison, which orders
 *     by UTF-16 code units. This is deterministic for any input that is
 *     itself deterministic; KERI event objects use ASCII keys, so this
 *     coincides with bytewise UTF-8 order in practice.
 *   - No insignificant whitespace is emitted.
 *   - Numbers must be finite. `NaN`, `Infinity`, `-Infinity`, and `-0`
 *     are rejected because their JSON representations are either invalid
 *     or implementation-defined.
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
			throw new CanonicalJsonError(
				'only plain objects are supported'
			);
		}
		const obj = value as Record<string, unknown>;
		const keys = Object.keys(obj).sort();
		const parts: string[] = [];
		for (const k of keys) {
			const v = obj[k];
			parts.push(JSON.stringify(k) + ':' + canonicalize(v));
		}
		return '{' + parts.join(',') + '}';
	}

	throw new CanonicalJsonError(`unsupported value type: ${type}`);
}
