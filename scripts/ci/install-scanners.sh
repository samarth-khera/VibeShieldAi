#!/usr/bin/env bash
# Installs (or verifies cache-restored) scanner tools into a runner-owned directory.
# Every binary is checked against a pinned SHA-256 before use; a mismatch or missing file is
# treated as a cache miss and reinstalled from the official release. Prints CACHE_STATUS lines
# so cache hits and misses are visible in the workflow log.
set -euo pipefail

TOOLS_DIR="${HOME}/.vibeshield"
BIN_DIR="${TOOLS_DIR}/bin"
VENV_DIR="${TOOLS_DIR}/semgrep-venv"
mkdir -p "${BIN_DIR}"

GITLEAKS_VERSION="${GITLEAKS_VERSION:?}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:?}"
SEMGREP_VERSION="${SEMGREP_VERSION:?}"

# Published checksums (release *_checksums.txt / *_SHA256SUMS) for linux x64.
GITLEAKS_TARBALL_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" # gitleaks_8.30.1_linux_x64.tar.gz
GITLEAKS_BINARY_SHA256="88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509"  # gitleaks inside that tarball
OSV_SCANNER_SHA256="160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"      # osv-scanner_linux_amd64 v2.7.0

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
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o "${tmp}/gitleaks.tgz"
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
  curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o "${BIN_DIR}/osv-scanner.download"
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
  python -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --disable-pip-version-check --quiet -r .github/scanner-requirements.txt
  [[ "$("${VENV_DIR}/bin/semgrep" --version | head -n1)" == "${SEMGREP_VERSION}" ]] || { echo "::error::semgrep version mismatch"; exit 1; }
fi
ln -sf "${VENV_DIR}/bin/semgrep" "${BIN_DIR}/semgrep"
# setup-python's pip-cache post step errors if the cache directory is missing (tool cache hit, pip cache evicted).
mkdir -p "$(python -m pip cache dir 2>/dev/null || echo "${HOME}/.cache/pip")"
echo "TIMING semgrep_ms=$(( $(now_ms) - t ))"

echo "${BIN_DIR}" >> "${GITHUB_PATH}"
echo "Scanner versions: gitleaks $("${BIN_DIR}/gitleaks" version), semgrep $("${BIN_DIR}/semgrep" --version | head -n1), $("${BIN_DIR}/osv-scanner" --version | head -n1)"
