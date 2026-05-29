/**
 * TypeScript half of the keripy interoperability bridge.
 *
 * The interop tests need to talk to the reference KERI implementation
 * (keripy). keripy is a Python library, so the conversation happens over a
 * child process: `keripy_bridge.py` is invoked with a sub-command, fed a JSON
 * request on stdin, and replies with a JSON document on stdout. This module
 * locates a usable Python interpreter and wraps that exchange in typed helpers.
 *
 * Locating the interpreter
 * ------------------------
 * keripy is not a dependency of this package — it is heavy and Python-only —
 * so it must be installed separately. `test/interop/setup-keripy.sh` builds a
 * virtualenv with keripy installed in a project-relative `./keripy` directory.
 * The interpreter is resolved, in order, from:
 *   1. the `KERIPY_PYTHON` environment variable, then
 *   2. the virtualenv `setup-keripy.sh` creates (`<repo>/keripy`), then
 *   3. `python3` on `PATH`.
 *
 * If no candidate can import keripy, `resolvePython()` throws and
 * `keripyAvailable()` returns false. keripy is an optional, separately-
 * provisioned dependency, so the interop suite skips itself in that case
 * rather than failing. Run `test/interop/setup-keripy.sh` to provision it.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

/** Absolute path to the Python bridge script. */
export const BRIDGE_SCRIPT = join(__dirname, 'keripy_bridge.py');

/**
 * The virtualenv interpreter that `setup-keripy.sh` provisions. It lives in a
 * project-relative `./keripy` directory at the repo root — two levels up from
 * `test/interop` — so the interop tests need nothing installed outside the repo.
 */
const VENV_PYTHON = join(__dirname, '..', '..', 'keripy', 'bin', 'python3');

let resolvedPython: string | undefined;
let resolutionError: Error | undefined;

/** Per-candidate rejection reasons, surfaced when the interop suite skips. */
const probeFailures: string[] = [];

/** Candidate interpreters, in resolution priority order. */
function pythonCandidates(): string[] {
	const candidates: string[] = [];
	if (process.env.KERIPY_PYTHON) candidates.push(process.env.KERIPY_PYTHON);
	candidates.push(VENV_PYTHON);
	candidates.push('python3');
	return candidates;
}

/**
 * True when `python` exists and can import the keripy `keri` package.
 *
 * Probes `keri.core.eventing` specifically: that submodule pulls in `pysodium`
 * (and so libsodium), `lmdb`, and the rest of keripy's native dependencies, so
 * importing it is a faithful proxy for "the bridge will actually work". On
 * failure the reason is recorded in `probeFailures` for the skip message.
 */
function canImportKeri(python: string): boolean {
	try {
		execFileSync(python, ['-c', 'import keri.core.eventing'], {
			stdio: ['ignore', 'ignore', 'pipe'],
		});
		return true;
	} catch (err) {
		const e = err as { stderr?: Buffer | string };
		const stderr = (e.stderr ? String(e.stderr) : '').trim();
		const detail = stderr.split('\n').pop() || 'cannot import keri.core.eventing';
		probeFailures.push(`${python}: ${detail}`);
		return false;
	}
}

/**
 * Resolve a Python interpreter with keripy installed, memoizing the result.
 *
 * Throws a descriptive error — pointing at `setup-keripy.sh` — when no
 * candidate works, so that interop tests fail loudly rather than skip.
 */
export function resolvePython(): string {
	if (resolvedPython) return resolvedPython;
	if (resolutionError) throw resolutionError;

	for (const candidate of pythonCandidates()) {
		// A bare command name (no separator) is resolved via PATH by execFileSync;
		// an explicit path must exist on disk before we probe it.
		const isPath = candidate.includes('/');
		if (isPath && !existsSync(candidate)) {
			probeFailures.push(`${candidate}: not found`);
			continue;
		}
		if (canImportKeri(candidate)) {
			resolvedPython = candidate;
			return resolvedPython;
		}
	}

	resolutionError = new Error(
		'keripy interop tests require a Python interpreter with the `keri` '
			+ 'package installed, but none was usable.\n'
			+ `Probed:\n  ${probeFailures.join('\n  ')}\n`
			+ 'Provision one by running: bash test/interop/setup-keripy.sh\n'
			+ 'or point KERIPY_PYTHON at an interpreter that has keripy installed.'
	);
	throw resolutionError;
}

/**
 * True when a Python interpreter with keripy installed can be resolved.
 *
 * Unlike `resolvePython`, this never throws: the interop suite calls it to
 * decide whether to run or skip. keripy is provisioned separately (into the
 * project-relative `./keripy` virtualenv by `setup-keripy.sh`, or via
 * `KERIPY_PYTHON`), so when it is absent the suite skips rather than fails.
 */
export function keripyAvailable(): boolean {
	try {
		resolvePython();
		return true;
	} catch {
		return false;
	}
}

/**
 * The reason the interop suite would skip — the per-candidate probe failures —
 * or an empty string when keripy is available. The suite logs this so a skip
 * is never silent: a broken or partial keripy install reads very differently
 * from "not installed at all".
 */
export function keripyUnavailableReason(): string {
	return keripyAvailable() ? '' : (resolutionError?.message ?? 'unknown');
}

/** Response of the `gen-kel` bridge command. */
export interface GenKelResult {
	aid: string;
	did: string;
	/** The KEL as a CESR stream — the same wire form node-keri produces. */
	kel: string;
}

/** Response of the `verify-kel` bridge command. */
export type VerifyKelResult =
	| { ok: true; aid: string; sn: number; said: string; currentKeys: string[] }
	| { ok: false; error: string };

/** Response of the `verify-extension` bridge command. */
export type VerifyExtensionResult =
	| { ok: true; snBefore: number; snAfter: number; rejected: boolean }
	| { ok: false; error: string };

/** Response of the `sign` bridge command. */
export interface SignResult {
	ok: true;
	publicKey: string;
	signature: string;
}

/**
 * Invoke a keripy bridge sub-command. The `input` object is sent as a JSON
 * request body; the JSON response is parsed and returned.
 *
 * Throws when the bridge process cannot be started, exits non-zero without a
 * JSON body, or emits output that is not valid JSON.
 */
export function runBridge<T>(command: string, input: unknown): T {
	const python = resolvePython();
	let stdout: string;
	try {
		stdout = execFileSync(python, [BRIDGE_SCRIPT, command], {
			input: JSON.stringify(input ?? {}),
			encoding: 'utf-8',
			maxBuffer: 16 * 1024 * 1024,
		});
	} catch (err) {
		// A non-zero exit still carries the structured JSON error on stdout;
		// surface that if present, otherwise re-throw the raw process failure.
		const e = err as { stdout?: string; stderr?: string; message?: string };
		const body = (e.stdout || '').trim();
		if (body) {
			try {
				return JSON.parse(body) as T;
			} catch {
				/* fall through to the thrown error below */
			}
		}
		throw new Error(
			`keripy bridge '${command}' failed: ${e.stderr || e.message || 'unknown error'}`
		);
	}
	try {
		return JSON.parse(stdout) as T;
	} catch {
		throw new Error(
			`keripy bridge '${command}' returned non-JSON output: ${stdout.slice(0, 400)}`
		);
	}
}

/** Generate a KEL with keripy and return it as a CESR stream. */
export function keripyGenKel(seeds: number[], anchor?: unknown): GenKelResult {
	return runBridge<GenKelResult>('gen-kel', { seeds, anchor });
}

/**
 * Generate a *non-transferable* AID and its single-event KEL with keripy,
 * returning the KEL as a CESR stream. node-keri verifies these; it does not
 * generate them.
 */
export function keripyGenNonTransferableKel(seed: number): GenKelResult {
	return runBridge<GenKelResult>('gen-nt-kel', { seed });
}

/**
 * Generate a KEL ending in a *deactivation* event with keripy, returning it as
 * a CESR stream. The KEL is `[icp, deactivation]` derived from the two seeds.
 */
export function keripyGenDeactivatedKel(seeds: number[]): GenKelResult {
	return runBridge<GenKelResult>('gen-deactivated-kel', { seeds });
}

/**
 * Generate an *establishment-only* KEL (icp with the `EO` trait, then two
 * rotations — never an interaction) with keripy, as a CESR stream.
 */
export function keripyGenEoKel(seeds: number[]): GenKelResult {
	return runBridge<GenKelResult>('gen-eo-kel', { seeds });
}

/**
 * Generate an `EO` inception followed by an interaction event with keripy. The
 * `ixn` is well-formed and signed; it violates the EO trait, so node-keri's
 * replay must reject it. The seeds are `[inceptionKey, nextKey]`.
 */
export function keripyGenEoIcpThenIxn(
	seeds: number[],
	anchor?: unknown
): GenKelResult {
	return runBridge<GenKelResult>('gen-eo-icp-then-ixn', { seeds, anchor });
}

/** Replay a node-keri CESR-stream KEL through keripy's verifier. */
export function keripyVerifyKel(aid: string, kel: string): VerifyKelResult {
	return runBridge<VerifyKelResult>('verify-kel', { aid, kel });
}

/**
 * Replay `kel` through keripy, then feed it `extension` and report whether
 * keripy refused to extend the KEL — the expected outcome when `kel` ends in
 * a deactivation event.
 */
export function keripyVerifyExtension(
	aid: string,
	kel: string,
	extension: string
): VerifyExtensionResult {
	return runBridge<VerifyExtensionResult>('verify-extension', {
		aid,
		kel,
		extension,
	});
}

/** Sign a payload with keripy's deterministic Ed25519 signer. */
export function keripySign(seed: number, payload: Uint8Array): SignResult {
	return runBridge<SignResult>('sign', {
		seed,
		payloadB64: Buffer.from(payload).toString('base64'),
	});
}

/** Verify a detached Ed25519 signature with keripy. */
export function keripyVerifySig(
	publicKey: string,
	payload: Uint8Array,
	signature: string
): boolean {
	const res = runBridge<{ ok: boolean }>('verify-sig', {
		publicKey,
		payloadB64: Buffer.from(payload).toString('base64'),
		signature,
	});
	return res.ok === true;
}
