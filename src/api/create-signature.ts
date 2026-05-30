/**
 * `createSignature` — sign a payload and return the signature in its
 * CESR-qualified wire form.
 *
 * It is the signing counterpart to `verifySignature`. The low-level `sign`
 * produces raw 64-byte Ed25519 output, but the rest of the public surface —
 * `verifySignature`, `verifySignatureWithDid` — speaks CESR-qualified strings.
 * `createSignature` does the `sign` + `encodeSignatureEd25519` step in one
 * call, so a caller never has to touch raw signature bytes:
 *
 *   const signature = createSignature(keyPair.privateKey, payload);
 *   verifySignature({ aid, kel, payload, signature });
 *
 * The result is a non-indexed signature (a "Cigar", code `0B`) — the form for
 * detached signatures over arbitrary payloads, as opposed to the indexed
 * signatures attached to KEL events.
 */

import { encodeSignatureEd25519 } from '../cesr/encode';
import { CesrSignature } from '../cesr/qualified';
import { sign } from '../crypto/ed25519';
import { PrivateKey } from '../crypto/keypair';

/**
 * Sign `payload` with `privateKey` and return the CESR-qualified signature.
 *
 * `privateKey` must be an Ed25519 `PrivateKey`; `sign` asserts this and throws
 * `InvalidArgumentError` otherwise.
 */
export function createSignature(
	privateKey: PrivateKey,
	payload: Readonly<Uint8Array>
): CesrSignature {
	return encodeSignatureEd25519(sign(privateKey, payload));
}
