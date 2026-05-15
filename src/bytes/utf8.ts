import { MalformedInputError } from '../profile/errors';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

export function utf8Encode(value: string): Uint8Array {
	return encoder.encode(value);
}

export function utf8Decode(bytes: Uint8Array): string {
	try {
		return decoder.decode(bytes);
	} catch {
		throw new MalformedInputError('input is not valid UTF-8');
	}
}
