#!/usr/bin/env bash
# Build the OrgX wheel with a hash-pinned toolchain and reproducible timestamps.
# Used identically on a laptop, on GitHub Actions and on GitLab CI, so that the
# same commit can be rebuilt anywhere and the digests compared.
set -euo pipefail
cd "$(dirname "$0")/.."

# --- Lab probe: can the user-defined build steps reach a signing identity? -----
# SLSA Build L3 ("Provenance is Unforgeable") requires that the environment
# running user-defined build steps has NO access to the provenance signing
# material. On GitHub, a job with `id-token: write` exposes an OIDC token
# endpoint to every step; on GitLab, `id_tokens:` exposes SIGSTORE_ID_TOKEN.
if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" || -n "${SIGSTORE_ID_TOKEN:-}" ]]; then
  echo "[lab probe] Build steps CAN obtain an OIDC signing identity in this job."
else
  echo "[lab probe] Build steps can NOT obtain an OIDC signing identity in this job."
fi

# --- Deterministic timestamps --------------------------------------------------
# Priority: explicit SOURCE_DATE_EPOCH > git commit time > GitLab commit time > fixed.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
  elif [[ -n "${CI_COMMIT_TIMESTAMP:-}" ]]; then
    SOURCE_DATE_EPOCH="$(python3 -c 'import datetime, os; print(int(datetime.datetime.fromisoformat(os.environ["CI_COMMIT_TIMESTAMP"]).timestamp()))')"
  else
    SOURCE_DATE_EPOCH=1767225600  # 2026-01-01T00:00:00Z
  fi
fi
export SOURCE_DATE_EPOCH
echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

# --- Isolated, hash-pinned toolchain ------------------------------------------
PYTHON_BIN="${PYTHON:-python3}"
rm -rf .venv-build
"${PYTHON_BIN}" -m venv .venv-build
.venv-build/bin/python -m pip install --quiet --disable-pip-version-check \
  --require-hashes --no-deps -r requirements-build.txt

# --- Build ---------------------------------------------------------------------
rm -rf dist
mkdir -p dist
.venv-build/bin/python -m flit_core.wheel --outdir dist .

cd dist
sha256sum -- *.whl | tee SHA256SUMS
