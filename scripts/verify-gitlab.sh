#!/usr/bin/env bash
# Consumer-side verification suite for the GitLab part of the lab (public project).
#
#   GL_PROJECT=<namespace>/orgx-parcel bash scripts/verify-gitlab.sh
#
# Needs: curl, unzip, python3 and cosign >= 2.2 on your laptop
# (https://docs.sigstore.dev/cosign/system_config/installation/).
set -uo pipefail

: "${GL_PROJECT:?set GL_PROJECT, e.g. GL_PROJECT=my-lab-namespace/orgx-parcel}"
GL_HOST="${GL_HOST:-https://gitlab.com}"
REF_NAME="${REF_NAME:-main}"
IDENTITY="${GL_HOST}/${GL_PROJECT}//.gitlab-ci.yml@refs/heads/${REF_NAME}"
ISSUER="${GL_HOST}"

cd "$(dirname "$0")/.." || exit 1
OUT=lab-output/gitlab
REPORT=lab-output/gitlab-results.md
mkdir -p "$OUT"

command -v cosign >/dev/null || { echo "Install cosign first (see header)"; exit 2; }

fetch() { # fetch <job> <dest>
  local url="${GL_HOST}/${GL_PROJECT}/-/jobs/artifacts/${REF_NAME}/download?job=$1"
  rm -rf "$2" && mkdir -p "$2"
  if curl -fsSL -o "$2/artifacts.zip" "$url"; then
    unzip -q -o "$2/artifacts.zip" -d "$2" && echo "  downloaded artifacts of job '$1'"
  else
    echo "  (no artifacts for job '$1' on ${REF_NAME} yet - related scenarios will be skipped)"
  fi
}
echo "Downloading artifacts ..."
fetch attest "$OUT/attest"
fetch rogue-attest "$OUT/rogue"

OFFICIAL_WHL="$(find "$OUT/attest/dist" -name '*.whl' 2>/dev/null | head -n1)"
OFFICIAL_BUNDLE="$OUT/attest/provenance.sigstore.json"
RUNNER_PROV="$OUT/attest/runner-provenance.json"
ROGUE_WHL="$(find "$OUT/rogue/rogue" -name '*.whl' 2>/dev/null | head -n1)"
ROGUE_BUNDLE="$OUT/rogue/rogue-provenance.sigstore.json"
TAMPERED=""
if [[ -n "$OFFICIAL_WHL" ]]; then
  mkdir -p "$OUT/tampered" && TAMPERED="$OUT/tampered/$(basename "$OFFICIAL_WHL")"
  cp "$OFFICIAL_WHL" "$TAMPERED" && printf 'backdoor' >> "$TAMPERED"
fi

{
  echo "# GitLab verification results"
  echo
  echo "Run on $(date -u +%Y-%m-%dT%H:%M:%SZ) with $(cosign version 2>/dev/null | grep -i gitversion | tr -s ' ')"
  echo
  echo "Expected identity: \`$IDENTITY\`"
  echo
  echo "| ID | SLSA threat | Scenario | Expected | Observed | Matches oracle |"
  echo "|----|-------------|----------|----------|----------|----------------|"
} > "$REPORT"

deviations=0
verify() { # verify <id> <threat> <description> <expected> <wheel> <bundle> <identity>
  local id="$1" threat="$2" desc="$3" expected="$4" wheel="$5" bundle="$6" identity="$7" observed match
  echo
  echo "=== $id [$threat] $desc (expected: $expected)"
  if [[ -z "$wheel" || ! -f "$wheel" || ! -f "$bundle" ]]; then
    echo "  skipped: artifact or bundle not available"
    echo "| $id | $threat | $desc | $expected | SKIPPED | - |" >> "$REPORT"
    return
  fi
  if cosign verify-blob-attestation --bundle "$bundle" --type https://slsa.dev/provenance/v1 \
       --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$wheel" > "$OUT/$id.log" 2>&1; then
    observed=PASS
  else
    observed=FAIL
  fi
  sed 's/^/  /' "$OUT/$id.log" | tail -n 6
  if [[ "$observed" == "$expected" ]]; then match=yes; else match=NO; deviations=$((deviations + 1)); fi
  echo "| $id | $threat | $desc | $expected | $observed | $match |" >> "$REPORT"
}

# ------------------------------------------------------------------ L1 evidence
if [[ -f "$RUNNER_PROV" ]]; then
  echo
  echo "=== GL1 Runner-generated L1 provenance (unsigned)"
  python3 - "$RUNNER_PROV" <<'EOF' | tee -a "$OUT/GL1.txt"
import json, sys
s = json.load(open(sys.argv[1]))
p = s.get("predicate", {})
print("  _type         :", s.get("_type"))
print("  predicateType :", s.get("predicateType"))
print("  subject       :", [(x.get("name"), x.get("digest", {}).get("sha256", "")[:16]) for x in s.get("subject", [])])
print("  builder.id    :", p.get("runDetails", {}).get("builder", {}).get("id"))
print("  buildType     :", p.get("buildDefinition", {}).get("buildType"))
print("  signature     : none (plain JSON file)")
EOF
  if [[ -n "$ROGUE_WHL" ]]; then
    python3 attacks/forge_gitlab_l1.py "$RUNNER_PROV" "$ROGUE_WHL" > "$OUT/forged-l1.json"
    echo "| GL1 | - | Runner provenance exists and is unsigned (L1) | info | see gitlab/GL1.txt | - |" >> "$REPORT"
    echo "| GL2 | D/E | L1 statement forged for the backdoored wheel | forgery undetectable | nothing to verify: no signature | yes |" >> "$REPORT"
  fi
fi

# ------------------------------------------------------------------ signed scenarios
verify GL3 "-"   "Official wheel + official signed attestation"           PASS "$OFFICIAL_WHL" "$OFFICIAL_BUNDLE" "$IDENTITY"
verify GL4 "F"   "Wheel modified after signing"                           FAIL "$TAMPERED"     "$OFFICIAL_BUNDLE" "$IDENTITY"
verify GL5 "D"   "Official wheel, consumer expects branch experimental"   FAIL "$OFFICIAL_WHL" "$OFFICIAL_BUNDLE" "${GL_HOST}/${GL_PROJECT}//.gitlab-ci.yml@refs/heads/experimental"
verify GL6 "F"   "Backdoored wheel presented with the official bundle"    FAIL "$ROGUE_WHL"    "$OFFICIAL_BUNDLE" "$IDENTITY"
verify GL7 "D/E" "Backdoored wheel signed by a rogue job, same pipeline"  PASS "$ROGUE_WHL"    "$ROGUE_BUNDLE"    "$IDENTITY"
echo "| GL8 | - | GitLab L3 attestation (Ultimate + feature flag) | not available | record manually | - |" >> "$REPORT"

echo
cat "$REPORT"
[[ $deviations -eq 0 ]] && echo "All executed scenarios matched the oracle." || echo "WARNING: $deviations deviation(s) - analyse them, they are findings."
