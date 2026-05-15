import { base64urlEncode, intToB64 } from '../bytes/base64url';
import { InvalidArgumentError } from '../profile/errors';
import {
	CESR_DIGEST_SHA256,
	CESR_INDEXED_SIGNATURE_ED25519,
	CESR_PUBLIC_KEY_ED25519,
	CESR_SIGNATURE_ED25519,
	CesrCodeSpec,
	digestSpecForCode,
} from './codes';
import {
	CesrDigest,
	CesrIndexedSignature,
	CesrPublicKey,
	CesrSignature,
} from './qualified';

/**
 * Produce the qualified base64 ("qb64") form of a CESR Matter primitive.
 *
 * The raw payload is prepended with `ps` zero bytes so that the total length
 * is a multiple of 3 and the base64url encoding therefore has no '=' padding.
 * Because the leading bytes are zero, the leading `ps` characters of the
 * encoded string are always 'A' (= 0); they are replaced by the code prefix.
 * For a plain primitive that prefix is just `spec.code` (with `hs === ps`); an
 * indexed primitive passes `prefix` explicitly (`hs` code chars + `ss` index
 * chars, together `ps` long).
 */
function encodeMatter(spec: CesrCodeSpec, raw: Uint8Array, prefix?: string): string {
	if (raw.length !== spec.rs) {
		throw new InvalidArgumentError(
			`${spec.label} requires ${spec.rs} raw bytes, got ${raw.length}`
		);
	}
	const padded = new Uint8Array(spec.ps + spec.rs);
	padded.set(raw, spec.ps);
	const b64 = base64urlEncode(padded);
	return (prefix ?? spec.code) + b64.slice(spec.ps);
}

/** CESR-qualify a 32-byte Ed25519 public key (transferable, code `D`). */
export function encodePublicKeyEd25519(raw: Uint8Array): CesrPublicKey {
	return encodeMatter(CESR_PUBLIC_KEY_ED25519, raw) as CesrPublicKey;
}

/** CESR-qualify a 64-byte Ed25519 signature, non-indexed (code `0B`). */
export function encodeSignatureEd25519(raw: Uint8Array): CesrSignature {
	return encodeMatter(CESR_SIGNATURE_ED25519, raw) as CesrSignature;
}

/**
 * CESR-qualify a 64-byte Ed25519 signature as an *indexed* signature (a
 * "Siger", code `A`). `index` is the position of the signing key within the
 * establishment event's key list and is encoded into the code's 1-character
 * soft field — so it must be 0–63. This single-key profile always signs at
 * index 0; the parameter exists for wire compatibility with KERI.
 */
export function encodeIndexedSignatureEd25519(
	raw: Uint8Array,
	index: number
): CesrIndexedSignature {
	const spec = CESR_INDEXED_SIGNATURE_ED25519;
	if (!Number.isInteger(index) || index < 0 || index > 63) {
		throw new InvalidArgumentError(
			`signature index must be an integer in [0, 63], got ${index}`
		);
	}
	const prefix = spec.code + intToB64(index, spec.ss);
	return encodeMatter(spec, raw, prefix) as CesrIndexedSignature;
}

/** CESR-qualify a 32-byte SHA-256 digest (code `I`), specifically. */
export function encodeDigestSha256(raw: Uint8Array): CesrDigest {
	return encodeMatter(CESR_DIGEST_SHA256, raw) as CesrDigest;
}

/**
 * CESR-qualify a raw digest under an explicit derivation `code`.
 *
 * `code` must be a supported digest width — a one-character (256-bit) or
 * `0`-prefixed two-character (512-bit) code — and `raw` must be exactly the
 * matching length (32 or 64 bytes); both are enforced here. This does not
 * require the algorithm to be *registered*: it is a pure structural encoding.
 */
export function encodeDigest(code: string, raw: Uint8Array): CesrDigest {
	return encodeMatter(digestSpecForCode(code), raw) as CesrDigest;
}
