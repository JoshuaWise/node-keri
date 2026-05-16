#!/usr/bin/env bash
#
# Provision a Python virtualenv with keripy (the reference KERI implementation)
# for the cross-implementation interop tests in test/keripy-interop.test.ts.
#
# keripy is intentionally NOT a dependency of node-keri — it is a large,
# Python-only package — so the interop tests reach it through a child process.
# This script builds the virtualenv those tests look for.
#
# Usage:
#   bash test/interop/setup-keripy.sh
#
# Everything is installed inside the repository, in a project-relative
# `./keripy` directory (git-ignored), so the interop tests can run without
# installing anything outside this repo. The TypeScript bridge
# (test/interop/bridge.ts) resolves that path automatically; alternatively set
# KERIPY_PYTHON to any interpreter that already has keripy installed and skip
# this script entirely.
#
# keripy depends on libsodium at runtime (via pysodium). This script installs
# it automatically when missing — Homebrew on macOS, the native package
# manager on Linux (apt/dnf/yum/zypper/pacman/apk). Set KERIPY_SKIP_LIBSODIUM=1
# to skip that step if you manage libsodium yourself.
set -euo pipefail

# Resolve the repository root from this script's location so the install is
# project-relative regardless of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VENV_DIR="${REPO_ROOT}/keripy"
WHEELS_DIR="${REPO_ROOT}/keripy-wheels"

# keripy 1.3.4 is the pinned reference version. hio 0.7.16 is the newest hio
# release that still supports Python 3.13 (later releases require 3.14+).
KERI_VERSION="1.3.4"
HIO_VERSION="0.7.16"

# keri 1.3.4 requires Python >= 3.12.2 and hio 0.7.16 tops out at 3.13, so the
# venv must be built with a 3.12.2–3.13.x interpreter. A bare `python3` is
# often older than that, which fails with a confusing "No matching
# distribution" error from pip — so pick a suitable interpreter explicitly.
# KERIPY_BASE_PYTHON overrides the search with a known-good interpreter.
find_python() {
	if [ -n "${KERIPY_BASE_PYTHON:-}" ]; then
		echo "${KERIPY_BASE_PYTHON}"
		return 0
	fi
	for candidate in python3.13 python3.12 python3; do
		command -v "${candidate}" >/dev/null 2>&1 || continue
		# Accept >= 3.12.2 and < 3.14 (the hio 0.7.16 ceiling).
		if "${candidate}" -c 'import sys; v = sys.version_info; sys.exit(0 if (3, 12, 2) <= v < (3, 14) else 1)' 2>/dev/null; then
			echo "${candidate}"
			return 0
		fi
	done
	return 1
}

if ! PYTHON="$(find_python)"; then
	echo "error: no suitable Python interpreter found." >&2
	echo "keri ${KERI_VERSION} needs Python >= 3.12.2 and hio ${HIO_VERSION} needs < 3.14." >&2
	echo "Install a Python 3.12.2-3.13.x, or set KERIPY_BASE_PYTHON to one." >&2
	exit 1
fi
echo "Using base interpreter: ${PYTHON} ($(${PYTHON} --version 2>&1))"

# --- libsodium ---------------------------------------------------------------
# keripy's pysodium dependency loads libsodium at import time, so the system
# shared library must be present before the interop tests can run.

# True when the libsodium shared library can be found on this system.
libsodium_present() {
	case "$(uname -s)" in
	Darwin)
		# Homebrew install locations: Apple Silicon and Intel respectively.
		[ -e /opt/homebrew/lib/libsodium.dylib ] && return 0
		[ -e /usr/local/lib/libsodium.dylib ] && return 0
		brew list --formula libsodium >/dev/null 2>&1 && return 0
		return 1
		;;
	*)
		# Linux: trust the dynamic linker cache first, then probe lib dirs.
		if command -v ldconfig >/dev/null 2>&1; then
			ldconfig -p 2>/dev/null | grep -q 'libsodium\.so' && return 0
		fi
		for dir in /usr/lib /usr/lib64 /usr/local/lib /lib /usr/lib/*-linux-gnu; do
			ls "${dir}"/libsodium.so* >/dev/null 2>&1 && return 0
		done
		return 1
		;;
	esac
}

# Install libsodium via the platform's package manager.
install_libsodium() {
	case "$(uname -s)" in
	Darwin)
		if ! command -v brew >/dev/null 2>&1; then
			echo "error: Homebrew not found — install libsodium manually" \
				"('brew install libsodium' once Homebrew is available)." >&2
			return 1
		fi
		echo "Installing libsodium with Homebrew"
		brew install libsodium
		;;
	*)
		# Use sudo only when not already root and sudo exists.
		local sudo=""
		if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
			sudo="sudo"
		fi
		if command -v apt-get >/dev/null 2>&1; then
			echo "Installing libsodium with apt-get"
			${sudo} apt-get update
			# Package name is release-specific; libsodium-dev is the stable fallback.
			${sudo} apt-get install -y libsodium23 \
				|| ${sudo} apt-get install -y libsodium-dev
		elif command -v dnf >/dev/null 2>&1; then
			echo "Installing libsodium with dnf"
			${sudo} dnf install -y libsodium
		elif command -v yum >/dev/null 2>&1; then
			echo "Installing libsodium with yum"
			${sudo} yum install -y libsodium
		elif command -v zypper >/dev/null 2>&1; then
			echo "Installing libsodium with zypper"
			${sudo} zypper install -y libsodium
		elif command -v pacman >/dev/null 2>&1; then
			echo "Installing libsodium with pacman"
			${sudo} pacman -S --noconfirm libsodium
		elif command -v apk >/dev/null 2>&1; then
			echo "Installing libsodium with apk"
			${sudo} apk add libsodium
		else
			echo "error: no supported package manager found —" \
				"install libsodium manually." >&2
			return 1
		fi
		;;
	esac
}

if [ "${KERIPY_SKIP_LIBSODIUM:-}" = "1" ]; then
	echo "Skipping libsodium check (KERIPY_SKIP_LIBSODIUM=1)"
elif libsodium_present; then
	echo "libsodium already installed"
else
	echo "libsodium not found — installing it"
	install_libsodium
	if ! libsodium_present; then
		echo "error: libsodium still not detected after install." >&2
		exit 1
	fi
fi

echo "Creating virtualenv at ${VENV_DIR}"
"${PYTHON}" -m venv "${VENV_DIR}"
PIP="${VENV_DIR}/bin/pip"

if [ -d "${WHEELS_DIR}" ] && ls "${WHEELS_DIR}"/*.whl >/dev/null 2>&1; then
	echo "Installing keripy offline from wheelhouse ${WHEELS_DIR}"
	"${PIP}" install --no-index --find-links "${WHEELS_DIR}" \
		"keri==${KERI_VERSION}"
else
	echo "Installing keripy from PyPI"
	"${PIP}" install "keri==${KERI_VERSION}" "hio==${HIO_VERSION}"
fi

echo
# Verify with the exact import the interop bridge probes. `keri.core.eventing`
# pulls in pysodium/libsodium and lmdb, so this catches a partial install
# (e.g. missing libsodium) that a shallow `import keri` would not — which would
# otherwise make the interop tests skip silently.
if ! "${VENV_DIR}/bin/python3" -c \
	'import keri, keri.core.eventing; print("keripy", keri.__version__, "installed OK")'; then
	echo >&2
	echo "error: keripy installed but 'import keri.core.eventing' failed." >&2
	echo "If this is a libsodium loading problem, install libsodium manually" >&2
	echo "and re-run (or re-run without KERIPY_SKIP_LIBSODIUM set)." >&2
	exit 1
fi
echo "Done. Interop tests will use ${VENV_DIR}/bin/python3"
