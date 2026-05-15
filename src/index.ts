// Foundation surface (Milestone 1). The full public API is defined in
// later milestones; for now the library exposes the typed errors and the
// primitive helpers used by every other module.

export {
	KeriError,
	InvalidArgumentError,
	UnsupportedAlgorithmError,
	MalformedInputError,
	CanonicalJsonError,
} from './profile/errors';
export type { KeriVerificationError } from './profile/errors';

export {
	KERI_PROFILE_NAME,
	SUPPORTED_KEY_ALGORITHM,
	SUPPORTED_DIGEST_ALGORITHM,
	ED25519_PUBLIC_KEY_BYTES,
	ED25519_PRIVATE_SEED_BYTES,
	ED25519_SIGNATURE_BYTES,
	SHA256_DIGEST_BYTES,
} from './profile/constants';
export type {
	SupportedKeyAlgorithm,
	SupportedDigestAlgorithm,
} from './profile/constants';

export { base64urlEncode, base64urlDecode } from './bytes/base64url';
export { utf8Encode, utf8Decode } from './bytes/utf8';
export { timingSafeEqual, bytesEqual, concatBytes } from './bytes/compare';

export { randomBytes } from './crypto/random';
export { sha256 } from './crypto/hash';
export {
	generateKeyPair,
	keyPairFromSeed,
	publicKeyFromRaw,
	exportPublicKeyRaw,
} from './crypto/keypair';
export type {
	KeriPublicKey,
	KeriPrivateKey,
	KeriKeyPair,
} from './crypto/keypair';
export { sign, verify } from './crypto/ed25519';

export { canonicalizeJson } from './event/canonical-json';

export {
	encodePublicKeyEd25519,
	encodeSignatureEd25519,
	encodeDigestSha256,
} from './cesr/encode';
export {
	decodePublicKeyEd25519,
	decodeSignatureEd25519,
	decodeDigestSha256,
} from './cesr/decode';
export type {
	CesrPublicKey,
	CesrSignature,
	CesrDigest,
} from './cesr/qualified';
