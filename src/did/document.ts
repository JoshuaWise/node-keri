/**
 * DID document generation for the `did:keri` method.
 *
 * A KERI DID document is a *projection* of verified key state: it carries no
 * history, only the single currently-authoritative signing key. The input
 * `state` must be a replay-verified `KeriState` — the type produced by
 * `verifyKel` (or, within the same process, by the event constructors).
 * Building a document straight from unverified events is deliberately not
 * possible through this function; `resolveDid` is the entry point that
 * verifies a KEL first and only then projects its result here.
 *
 * The document follows the W3C DID Core data model with a single Ed25519
 * verification method expressed as `JsonWebKey2020` / `publicKeyJwk`, and is
 * referenced from both `authentication` and `assertionMethod`. It is plain
 * JSON-safe data: the caller serializes and publishes it.
 */

import { base64urlEncode } from '../bytes/base64url';
import { decodeVerificationKeyEd25519 } from '../cesr/decode';
import { DidKeri } from './did-keri';
import { KeriState } from '../kel/state';
import { InvalidArgumentError } from '../profile/errors';

/** A `service` entry as defined by the W3C DID Core data model. */
export type DidServiceEndpoint =
	| string
	| { readonly [key: string]: unknown }
	| readonly (string | { readonly [key: string]: unknown })[];

export interface DidService {
	/**
	 * Service identifier. A bare fragment (`#agent`) is expanded against the
	 * document's DID; any other string is used verbatim.
	 */
	readonly id: string;
	readonly type: string | readonly string[];
	readonly serviceEndpoint: DidServiceEndpoint;
}

/** A single Ed25519 verification method in JWK form. */
export interface DidVerificationMethod {
	readonly id: string;
	readonly type: 'JsonWebKey2020';
	readonly controller: string;
	readonly publicKeyJwk: {
		readonly kty: 'OKP';
		readonly crv: 'Ed25519';
		readonly x: string;
	};
}

/**
 * A `did:keri` DID document reflecting one verified key state.
 *
 * For a *deactivated* identifier the document is empty of authority:
 * `verificationMethod`, `authentication`, and `assertionMethod` are all empty
 * arrays and `service` is absent. An abandoned identifier makes no key
 * authoritative — see `createDidDocument`.
 */
export interface DidDocument {
	readonly '@context': readonly string[];
	readonly id: string;
	readonly verificationMethod: readonly DidVerificationMethod[];
	readonly authentication: readonly string[];
	readonly assertionMethod: readonly string[];
	readonly service?: readonly DidService[];
}

export interface CreateDidDocumentInput {
	/** Replay-verified state — the only kind of state safe to project. */
	readonly state: KeriState;
	/**
	 * The DID the document is for. Optional and redundant with `state.did`;
	 * when supplied it must match, which guards against pairing a state with
	 * the wrong identifier.
	 */
	readonly did?: DidKeri;
	/** Optional service endpoints to advertise. */
	readonly services?: readonly DidService[];
}

/**
 * JSON-LD contexts for the document. The DID Core v1 context defines the
 * document shape; the JWS-2020 suite context defines `JsonWebKey2020` and
 * `publicKeyJwk`, which the DID Core context alone does not.
 */
const DID_CONTEXT = [
	'https://www.w3.org/ns/did/v1',
	'https://w3id.org/security/suites/jws-2020/v1',
] as const;

/** Fragment of the (single) verification method within the document. */
const KEY_FRAGMENT = '#key-0';

/**
 * Generate a DID document for the verified `state`.
 *
 * The resulting document advertises exactly one verification method: the
 * signing key currently authoritative per the replayed KEL. Earlier keys are
 * not retained — a DID document describes present control, while history
 * lives in the KEL.
 *
 * A *deactivated* identifier is the exception: it has been abandoned, so it
 * makes no key authoritative. Its document carries no verification method and
 * no verification relationships, and any `services` are dropped. A consumer
 * should additionally treat `deactivated` resolution metadata as decisive.
 */
export function createDidDocument(input: CreateDidDocumentInput): DidDocument {
	if (input === null || typeof input !== 'object') {
		throw new InvalidArgumentError('createDidDocument requires an input object');
	}
	const state = input.state;
	if (state === null || typeof state !== 'object' || typeof state.did !== 'string') {
		throw new InvalidArgumentError('createDidDocument requires a verified KeriState');
	}
	const did = state.did;
	if (input.did !== undefined && input.did !== did) {
		throw new InvalidArgumentError(
			'createDidDocument: `did` does not match `state.did`'
		);
	}

	// A deactivated identifier is abandoned: project an authority-free
	// document. There is no key to advertise and nothing to point a
	// verification relationship at.
	if (state.deactivated) {
		return {
			'@context': [...DID_CONTEXT],
			id: did,
			verificationMethod: [],
			authentication: [],
			assertionMethod: [],
		};
	}

	if (typeof state.currentPublicKey !== 'string') {
		throw new InvalidArgumentError('createDidDocument requires a verified KeriState');
	}

	// `state.currentPublicKey` is CESR-qualified; the JWK `x` member is the
	// raw 32-byte Ed25519 key in unpadded base64url. The key is transferable
	// (`D`) or, for a non-transferable AID, non-transferable (`B`) — either way
	// the raw bytes are a plain Ed25519 public key.
	const rawKey = decodeVerificationKeyEd25519(state.currentPublicKey);
	const keyId = did + KEY_FRAGMENT;
	const verificationMethod: DidVerificationMethod = {
		id: keyId,
		type: 'JsonWebKey2020',
		controller: did,
		publicKeyJwk: {
			kty: 'OKP',
			crv: 'Ed25519',
			x: base64urlEncode(rawKey),
		},
	};

	if (input.services !== undefined && !Array.isArray(input.services)) {
		throw new InvalidArgumentError('createDidDocument: `services` must be an array');
	}
	const services = (input.services ?? []).map((service, index) =>
		normalizeService(service, did, index)
	);

	const document: DidDocument = {
		'@context': [...DID_CONTEXT],
		id: did,
		verificationMethod: [verificationMethod],
		authentication: [keyId],
		assertionMethod: [keyId],
		...(services.length > 0 ? { service: services } : {}),
	};
	return document;
}

/** Validate a caller-supplied service entry and expand a bare-fragment id. */
function normalizeService(service: DidService, did: DidKeri, index: number): DidService {
	if (service === null || typeof service !== 'object') {
		throw new InvalidArgumentError(`services[${index}] must be an object`);
	}
	if (typeof service.id !== 'string' || service.id.length === 0) {
		throw new InvalidArgumentError(
			`services[${index}].id must be a non-empty string`
		);
	}
	const type = service.type;
	const typeOk =
		(typeof type === 'string' && type.length > 0)
		|| (Array.isArray(type)
			&& type.length > 0
			&& type.every((t) => typeof t === 'string' && t.length > 0));
	if (!typeOk) {
		throw new InvalidArgumentError(
			`services[${index}].type must be a non-empty string or array of non-empty strings`
		);
	}
	if (service.serviceEndpoint === undefined || service.serviceEndpoint === null) {
		throw new InvalidArgumentError(`services[${index}].serviceEndpoint is required`);
	}
	return {
		id: service.id.startsWith('#') ? did + service.id : service.id,
		type: service.type,
		serviceEndpoint: service.serviceEndpoint,
	};
}
