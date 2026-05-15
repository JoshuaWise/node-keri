/**
 * Branded string types for the qualified ("qb64") CESR forms in this subset.
 *
 * At runtime these are plain strings — the brand only exists at compile time
 * so a `CesrPublicKey` cannot be silently passed where a `CesrSignature` is
 * expected. Decoders accept raw `string` because their input is by definition
 * untrusted (a CESR field plucked from JSON, the network, etc.); the encoders
 * return the branded form, which is the only way to mint one.
 */

declare const cesrBrand: unique symbol;

export type CesrPublicKey = string & {
	readonly [cesrBrand]: 'PublicKeyEd25519';
};

export type CesrSignature = string & {
	readonly [cesrBrand]: 'SignatureEd25519';
};

export type CesrDigest = string & {
	readonly [cesrBrand]: 'DigestSha256';
};
