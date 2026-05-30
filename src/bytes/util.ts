/** Variable-time byte equality. Use for non-secret comparisons only. */
export function bytesEqual(a: Readonly<Uint8Array>, b: Readonly<Uint8Array>): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

/** Concatenate byte arrays into a single new buffer. */
export function concatBytes(...arrays: Readonly<Uint8Array>[]): Uint8Array {
	let total = 0;
	for (const a of arrays) total += a.length;
	const out = new Uint8Array(total);
	let offset = 0;
	for (const a of arrays) {
		out.set(a, offset);
		offset += a.length;
	}
	return out;
}
