// See PROFILE.md for the conformance boundary and SECURITY.md for the trust
// model and security invariants this API surface enforces.

export type { SupportedKeyAlgorithm } from './profile/constants';
export { KERI_PROFILE_NAME, SUPPORTED_KEY_ALGORITHM } from './profile/constants';

export type { DigestAlgorithm } from './crypto/digests';
export { digestAlgorithms, DIGEST_CODES, DEFAULT_DIGEST_CODE } from './crypto/digests';

export type { Aid, DidKeri } from './did/did-keri';
export type { CesrPublicKey, CesrSignature, CesrDigest } from './cesr/qualified';
export type { KeriEventType } from './event/types';

export type { PublicKey, PrivateKey, KeyPair } from './crypto/keypair';
export {
	generateKeyPair,
	asPublicKey,
	asPrivateKey,
	publicKeyToCesr,
	publicKeyFromCesr,
} from './crypto/keypair';

export type {
	KeriState,
	TransferableKeriState,
	NonTransferableKeriState,
	DeactivatedKeriState,
} from './kel/state';

export type {
	CreateIdentifierInput,
	CreateIdentifierResult,
} from './api/create-identifier';
export { createIdentifier } from './api/create-identifier';

export type {
	CreateNonTransferableIdentifierInput,
	CreateNonTransferableIdentifierResult,
} from './api/create-non-transferable-identifier';
export { createNonTransferableIdentifier } from './api/create-non-transferable-identifier';

export type {
	RotateIdentifierInput,
	RotateIdentifierResult,
} from './api/rotate-identifier';
export { rotateIdentifier } from './api/rotate-identifier';

export type {
	DeactivateIdentifierInput,
	DeactivateIdentifierResult,
} from './api/deactivate-identifier';
export { deactivateIdentifier } from './api/deactivate-identifier';

export type {
	InteractOnIdentifierInput,
	InteractOnIdentifierResult,
} from './api/interact-on-identifier';
export { interactOnIdentifier } from './api/interact-on-identifier';

export type {
	VerifyIdentifierInput,
	VerifyIdentifierResult,
} from './api/verify-identifier';
export { verifyIdentifier } from './api/verify-identifier';

export type { VerifyDidInput, VerifyDidResult } from './did/verify-did';
export { verifyDid } from './did/verify-did';

export type { VerifySignatureInput } from './api/verify-signature';
export { verifySignature } from './api/verify-signature';
export { createSignature } from './api/create-signature';

export type { VerifySignatureWithDidInput } from './did/verify-signature-with-did';
export { verifySignatureWithDid } from './did/verify-signature-with-did';

export type {
	CreateDidDocumentInput,
	DidDocument,
	DidVerificationMethod,
	DidService,
	DidServiceEndpoint,
} from './did/document';
export { createDidDocument } from './did/document';

export type { SignedKeriEvent } from './event/types';
export { parseKel } from './event/stream';
export { deriveNextKeyCommitment } from './event/digest';
export { canonicalizeJson } from './event/canonical-json';
export { utf8Encode, utf8Decode } from './bytes/utf8';

export type { KeriVerificationError } from './profile/errors';
export {
	KeriError,
	InvalidArgumentError,
	UnsupportedAlgorithmError,
	MalformedInputError,
	CanonicalJsonError,
} from './profile/errors';
