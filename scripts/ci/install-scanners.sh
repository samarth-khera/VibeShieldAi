#!/usr/bin/env bash
# Installs (or verifies cache-restored) scanner tools into a non-root, user-owned directory.
# Used by the GitHub Actions worker and by the persistent warm worker host (linux x64 or arm64).
# Every binary is checked against a pinned SHA-256 before use; a mismatch or missing file is
# treated as a cache miss and reinstalled from the official release. Prints CACHE_STATUS lines
# so cache hits and misses are visible in the workflow log.
set -euo pipefail

TOOLS_DIR="${VIBESHIELD_TOOLS_DIR:-${HOME}/.vibeshield}"
BIN_DIR="${TOOLS_DIR}/bin"
VENV_DIR="${TOOLS_DIR}/semgrep-venv"
mkdir -p "${BIN_DIR}"

GITLEAKS_VERSION="${GITLEAKS_VERSION:?}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:?}"
SEMGREP_VERSION="${SEMGREP_VERSION:?}"

# Published checksums (release *_checksums.txt / *_SHA256SUMS); binary hashes taken from those tarballs.
case "$(uname -m)" in
  x86_64|amd64)
    GL_ARCH="x64"; OSV_ARCH="amd64"
    GITLEAKS_TARBALL_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" # gitleaks_8.30.1_linux_x64.tar.gz
    GITLEAKS_BINARY_SHA256="88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"  # gitleaks inside that tarball
    OSV_SCANNER_SHA256="160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"      # osv-scanner_linux_amd64 v2.7.0
    ;;
  aarch64|arm64)
    GL_ARCH="arm64"; OSV_ARCH="arm64"
    GITLEAKS_TARBALL_SHA256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" # gitleaks_8.30.1_linux_arm64.tar.gz
    GITLEAKS_BINARY_SHA256="00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b"  # gitleaks inside that tarball
    OSV_SCANNER_SHA256="4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"      # osv-scanner_linux_arm64 v2.7.0
    ;;
  *) echo "::error::Unsupported architecture $(uname -m)"; exit 1 ;;
esac
PYTHON="$(command -v python || command -v python3)"
REQUIREMENTS="${VIBESHIELD_SCANNER_REQUIREMENTS:-.github/scanner-requirements.txt}"

if [[ "${GITLEAKS_VERSION}" != "8.30.1" || "${OSV_SCANNER_VERSION}" != "2.7.0" ]]; then
  echo "::error::Pinned checksums in install-scanners.sh do not match the requested scanner versions."
  exit 1
fi

sha_ok() { echo "$2  $1" | sha256sum --check --status; }
now_ms() { date +%s%3N; }

t=$(now_ms)
if [[ -f "${BIN_DIR}/gitleaks" ]] && sha_ok "${BIN_DIR}/gitleaks" "${GITLEAKS_BINARY_SHA256}"; then
  echo "CACHE_STATUS gitleaks=hit"
else
  echo "CACHE_STATUS gitleaks=miss"
  tmp="$(mktemp -d)"
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" -o "${tmp}/gitleaks.tgz"
  sha_ok "${tmp}/gitleaks.tgz" "${GITLEAKS_TARBALL_SHA256}" || { echo "::error::gitleaks tarball checksum mismatch"; exit 1; }
  tar -xzf "${tmp}/gitleaks.tgz" -C "${tmp}" gitleaks
  install -m 0755 "${tmp}/gitleaks" "${BIN_DIR}/gitleaks"
  sha_ok "${BIN_DIR}/gitleaks" "${GITLEAKS_BINARY_SHA256}" || { echo "::error::gitleaks binary checksum mismatch"; exit 1; }
  rm -rf "${tmp}"
fi
echo "TIMING gitleaks_ms=$(( $(now_ms) - t ))"

t=$(now_ms)
if [[ -f "${BIN_DIR}/osv-scanner" ]] && sha_ok "${BIN_DIR}/osv-scanner" "${OSV_SCANNER_SHA256}"; then
  echo "CACHE_STATUS osv-scanner=hit"
else
  echo "CACHE_STATUS osv-scanner=miss"
  curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${OSV_ARCH}" -o "${BIN_DIR}/osv-scanner.download"
  sha_ok "${BIN_DIR}/osv-scanner.download" "${OSV_SCANNER_SHA256}" || { echo "::error::osv-scanner checksum mismatch"; exit 1; }
  install -m 0755 "${BIN_DIR}/osv-scanner.download" "${BIN_DIR}/osv-scanner"
  rm -f "${BIN_DIR}/osv-scanner.download"
fi
echo "TIMING osv_ms=$(( $(now_ms) - t ))"

t=$(now_ms)
if [[ -x "${VENV_DIR}/bin/semgrep" ]] && [[ "$("${VENV_DIR}/bin/semgrep" --version 2>/dev/null | head -n1)" == "${SEMGREP_VERSION}" ]]; then
  echo "CACHE_STATUS semgrep=hit"
else
  echo "CACHE_STATUS semgrep=miss"
  rm -rf "${VENV_DIR}"
  "${PYTHON}" -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --disable-pip-version-check --quiet -r "${REQUIREMENTS}"
  [[ "$("${VENV_DIR}/bin/semgrep" --version | head -n1)" == "${SEMGREP_VERSION}" ]] || { echo "::error::semgrep version mismatch"; exit 1; }
fi
ln -sf "${VENV_DIR}/bin/semgrep" "${BIN_DIR}/semgrep"
# setup-python's pip-cache post step errors if the cache directory is missing (tool cache hit, pip cache evicted).
mkdir -p "$("${PYTHON}" -m pip cache dir 2>/dev/null || echo "${HOME}/.cache/pip")"
echo "TIMING semgrep_ms=$(( $(now_ms) - t ))"

if [[ -n "${GITHUB_PATH:-}" ]]; then echo "${BIN_DIR}" >> "${GITHUB_PATH}"; fi
echo "Scanner versions: gitleaks $("${BIN_DIR}/gitleaks" version), semgrep $("${BIN_DIR}/semgrep" --version | head -n1), $("${BIN_DIR}/osv-scanner" --version | head -n1)"
