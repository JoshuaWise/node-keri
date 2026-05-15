// Public surface up through Milestone 5. Higher-level entry points
// (`createIdentifier`, `rotateIdentifier`) are added by later milestones;
// what's exported here is the foundation, CESR primitives, the event
// lifecycle building blocks, the KEL replay verifier, and the DID surface —
// `did:keri` parsing, document generation, and local resolution.

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

export {
	DID_KERI_PREFIX,
	aidFromSaid,
	formatDidKeri,
	parseDidKeri,
} from './did/did-keri';
export type { Aid, DidKeri, ParsedDidKeri } from './did/did-keri';

export type {
	KeriEventType,
	KeriEventBase,
	InceptionEvent,
	RotationEvent,
	InteractionEvent,
	KeriEvent,
	SignedKeriEvent,
} from './event/types';

export type { KeriState } from './kel/state';

export {
	KERI_VERSION_STRING_LENGTH,
	SAID_PLACEHOLDER,
	computeEventSaid,
	deriveNextKeyCommitment,
	formatKeriVersionString,
} from './event/digest';
export { serializeEvent, signEvent } from './event/sign';
export { verifyEventSignature } from './event/verify-signature';

export { createInceptionEvent } from './event/inception';
export type {
	CreateInceptionInput,
	CreateInceptionResult,
} from './event/inception';

export { createRotationEvent } from './event/rotation';
export type {
	CreateRotationInput,
	CreateRotationResult,
} from './event/rotation';

export { createInteractionEvent } from './event/interaction';
export type {
	CreateInteractionInput,
	CreateInteractionResult,
} from './event/interaction';

export { verifyKel } from './api/verify-kel';
export type { VerifyKelInput, VerifyKelResult } from './api/verify-kel';

export { createDidDocument } from './did/document';
export type {
	CreateDidDocumentInput,
	DidDocument,
	DidVerificationMethod,
	DidService,
	DidServiceEndpoint,
} from './did/document';

export { resolveDid } from './did/resolver';
export type {
	ResolveDidInput,
	DidResolutionResult,
	DidResolutionMetadata,
} from './did/resolver';
