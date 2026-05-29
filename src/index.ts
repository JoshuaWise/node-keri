// Public API v1 — the stable surface of the KERI Direct JSON Profile.
//
// Three layers are exported: the foundation (bytes, crypto, CESR, canonical
// JSON), the event lifecycle building blocks plus the KEL replay verifier,
// and the high-level identifier API — `createIdentifier`, `rotateIdentifier`,
// `interactIdentifier`, `verifyKel`, the `did:keri` surface, and
// `verifySignatureWithDid` for signed message verification.
//
// See PROFILE.md for the conformance boundary and SECURITY.md for the trust
// model and security invariants this surface enforces.

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
	digestAlgorithms,
	runDigest,
	isRegisteredDigestCode,
	DIGEST_CODES,
	DEFAULT_DIGEST_CODE,
} from './crypto/digests';
export type { DigestAlgorithm } from './crypto/digests';
export {
	generateKeyPair,
	keyPairFromSeed,
	keyPairFromPrivateKey,
	publicKeyFromRaw,
	exportPublicKeyRaw,
	exportPublicKey,
} from './crypto/keypair';
export type {
	KeriPublicKey,
	KeriPrivateKey,
	KeriKeyPair,
	PublicKeyJwk,
} from './crypto/keypair';
export { sign, verify } from './crypto/ed25519';

export { canonicalizeJson } from './event/canonical-json';

export {
	encodePublicKeyEd25519,
	encodeSignatureEd25519,
	encodeIndexedSignatureEd25519,
	encodeDigestSha256,
	encodeDigest,
} from './cesr/encode';
export {
	decodePublicKeyEd25519,
	decodeNonTransferablePublicKeyEd25519,
	decodeVerificationKeyEd25519,
	decodeSignatureEd25519,
	decodeIndexedSignatureEd25519,
	signatureIndex,
	decodeDigestSha256,
	decodeDigest,
} from './cesr/decode';
export { digestCodeOf, digestSpecForCode } from './cesr/codes';
export type {
	CesrPublicKey,
	CesrSignature,
	CesrIndexedSignature,
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
	InceptionConfigTraits,
	InceptionEvent,
	NonTransferableInceptionEvent,
	RotationEvent,
	DeactivationEvent,
	InteractionEvent,
	KeriEvent,
	SignedKeriEvent,
} from './event/types';
export { KERI_CONFIG_TRAIT_ESTABLISHMENT_ONLY } from './event/types';

export type {
	KeriState,
	TransferableKeriState,
	NonTransferableKeriState,
	DeactivatedKeriState,
} from './kel/state';

export {
	KERI_VERSION_STRING_LENGTH,
	SAID_PLACEHOLDER,
	saidPlaceholder,
	computeEventSaid,
	deriveNextKeyCommitment,
	formatKeriVersionString,
} from './event/digest';
export { serializeEvent, signEvent } from './event/sign';
export { verifyEventSignature } from './event/verify-signature';
export { encodeEventFrame, parseSignedEvent, parseKel } from './event/stream';

export { createInceptionEvent } from './event/inception';
export type { CreateInceptionInput, CreateInceptionResult } from './event/inception';

export { createRotationEvent } from './event/rotation';
export type { CreateRotationInput, CreateRotationResult } from './event/rotation';

export { createDeactivationEvent } from './event/deactivation';
export type {
	CreateDeactivationInput,
	CreateDeactivationResult,
} from './event/deactivation';

export { createInteractionEvent } from './event/interaction';
export type {
	CreateInteractionInput,
	CreateInteractionResult,
} from './event/interaction';

export { createIdentifier } from './api/create-identifier';
export type {
	CreateIdentifierInput,
	CreateIdentifierResult,
} from './api/create-identifier';

export { rotateIdentifier } from './api/rotate-identifier';
export type {
	RotateIdentifierInput,
	RotateIdentifierResult,
} from './api/rotate-identifier';

export { deactivateIdentifier } from './api/deactivate-identifier';
export type {
	DeactivateIdentifierInput,
	DeactivateIdentifierResult,
} from './api/deactivate-identifier';

export { interactIdentifier } from './api/interact-identifier';
export type {
	InteractIdentifierInput,
	InteractIdentifierResult,
} from './api/interact-identifier';

export { verifyKel } from './api/verify-kel';
export type { VerifyKelInput, VerifyKelResult } from './api/verify-kel';

export { verifySignatureWithDid } from './api/verify-signature-with-did';
export type { VerifySignatureWithDidInput } from './api/verify-signature-with-did';

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
