#!/usr/bin/env bash
# Consumer-side verification suite for the GitHub part of the lab.
# Run it on your laptop AFTER the workflows have run (README, section "GitHub").
#
#   OWNER=<your-github-account> bash scripts/verify-github.sh
#
# Each scenario states the EXPECTED outcome (the test oracle) before running.
# Results go to lab-output/github-results.md - paste them into RESULTS.md.
set -uo pipefail

: "${OWNER:?set OWNER to your GitHub account, e.g. OWNER=my-lab-account}"
REPO="${REPO:-$OWNER/orgx-parcel}"
EVIL_REPO="${EVIL_REPO:-$OWNER/orgx-parcel-evil}"
L2_WORKFLOW="$REPO/.github/workflows/l2-build-attest.yml"
BUILDER="${BUILDER:-$OWNER/orgx-trusted-builder/.github/workflows/build-python-wheel.yml}"
TAG="${TAG:-v0.1.0}"

cd "$(dirname "$0")/.." || exit 1
OUT=lab-output/github
mkdir -p "$OUT"
REPORT=lab-output/github-results.md

command -v gh >/dev/null || { echo "Install the GitHub CLI (https://cli.github.com) and run 'gh auth login'"; exit 2; }

# ------------------------------------------------------------------ download
fetch() { # fetch <repo> <workflow-file> <artifact-name> <dest> [branch]
  local repo="$1" workflow="$2" name="$3" dest="$4" branch="${5:-}" run_id
  local args=(-R "$repo" --workflow "$workflow" --status success --limit 1 --json databaseId --jq '.[0].databaseId')
  [[ -n "$branch" ]] && args+=(--branch "$branch")
  run_id="$(gh run list "${args[@]}" 2>/dev/null)"
  if [[ -z "$run_id" || "$run_id" == "null" ]]; then
    echo "  (no successful run of $workflow in $repo${branch:+ on $branch} yet - scenario will be skipped)"
    return 1
  fi
  rm -rf "$dest" && mkdir -p "$dest"
  gh run download "$run_id" -R "$repo" -n "$name" -D "$dest" >/dev/null && echo "  downloaded $name from run $run_id"
}
wheel_in() { find "$1" -name '*.whl' 2>/dev/null | head -n1; }

echo "Downloading artifacts ..."
fetch "$REPO" l2-build-attest.yml orgx-parcel-dist "$OUT/l2"
fetch "$REPO" l3-release.yml orgx-parcel-dist "$OUT/l3"
fetch "$REPO" rogue-attest.yml rogue-dist "$OUT/rogue"
fetch "$EVIL_REPO" l2-build-attest.yml orgx-parcel-dist "$OUT/evil"
fetch "$REPO" l2-build-attest.yml orgx-parcel-dist "$OUT/branch" experimental

L2_WHL="$(wheel_in "$OUT/l2")"
L3_WHL="$(wheel_in "$OUT/l3")"
ROGUE_WHL="$(wheel_in "$OUT/rogue")"
EVIL_WHL="$(wheel_in "$OUT/evil")"
BRANCH_WHL="$(wheel_in "$OUT/branch")"
if [[ -n "$L2_WHL" ]]; then
  TAMPERED="$OUT/tampered/$(basename "$L2_WHL")"
  mkdir -p "$OUT/tampered" && cp "$L2_WHL" "$TAMPERED" && printf 'backdoor' >> "$TAMPERED"
else
  TAMPERED=""
fi

{
  echo "# GitHub verification results"
  echo
  echo "Run on $(date -u +%Y-%m-%dT%H:%M:%SZ) with $(gh --version | head -n1)"
  echo
  echo "| ID | SLSA threat | Scenario | Policy (flags) | Expected | Observed | Matches oracle | Time (s) |"
  echo "|----|-------------|----------|----------------|----------|----------|----------------|----------|"
} > "$REPORT"

deviations=0
now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
run() { # run <id> <threat> <description> <expected> <wheel> <gh flags...>
  local id="$1" threat="$2" desc="$3" expected="$4" wheel="$5"; shift 5
  echo
  echo "=== $id [$threat] $desc (expected: $expected)"
  if [[ -z "$wheel" || ! -f "$wheel" ]]; then
    echo "  skipped: artifact not available"
    echo "| $id | $threat | $desc | \`$*\` | $expected | SKIPPED | - | - |" >> "$REPORT"
    return
  fi
  local start end observed match seconds
  start=$(now)
  if gh attestation verify "$wheel" "$@" > "$OUT/$id.log" 2>&1; then observed=PASS; else observed=FAIL; fi
  end=$(now)
  seconds=$(python3 -c "print(f'{$end - $start:.1f}')")
  sed 's/^/  /' "$OUT/$id.log" | tail -n 12
  if [[ "$observed" == "$expected" ]]; then match=yes; else match=NO; deviations=$((deviations + 1)); fi
  echo "| $id | $threat | $desc | \`$*\` | $expected | $observed | $match | $seconds |" >> "$REPORT"
}

# ------------------------------------------------------------------ scenarios
# Order matters (README, step G6): attestations are attached to DIGESTS, and
# this build is reproducible, so two builds of the same commit give the same
# digest and share each other's attestations. The evil copy and the branch
# therefore carry their own commits, and the latest L2 run is made on a commit
# that was NOT released through the trusted builder.
run G1  "-"   "L2 official wheel, repository only"                    PASS "$L2_WHL"     --repo "$REPO"
run G2  "-"   "L2 official wheel, signer workflow pinned"             PASS "$L2_WHL"     --repo "$REPO" --signer-workflow "$L2_WORKFLOW"
run G3  "F"   "Wheel modified after the build"                        FAIL "$TAMPERED"   --repo "$REPO"
run G4  "D"   "Backdoored wheel built in another repo (evil copy)"    FAIL "$EVIL_WHL"   --repo "$REPO"
run G5  "D"   "Same evil wheel, owner-only policy (too loose)"        PASS "$EVIL_WHL"   --owner "$OWNER"
run G6  "D/E" "Rogue-workflow wheel, repository-only policy"          PASS "$ROGUE_WHL"  --repo "$REPO"
run G7  "D/E" "Rogue-workflow wheel, signer workflow pinned"          FAIL "$ROGUE_WHL"  --repo "$REPO" --signer-workflow "$L2_WORKFLOW"
run G8  "D"   "Wheel built from branch experimental, main required"   FAIL "$BRANCH_WHL" --repo "$REPO" --source-ref refs/heads/main
run G9  "-"   "Release via the trusted builder (L3 policy)"           PASS "$L3_WHL"     --repo "$REPO" --signer-workflow "$BUILDER" --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
run G10 "E"   "L2 wheel of an unreleased commit, L3 policy"           FAIL "$L2_WHL"     --repo "$REPO" --signer-workflow "$BUILDER"
run G11 "D/E" "Rogue-workflow wheel, L3 policy"                       FAIL "$ROGUE_WHL"  --repo "$REPO" --signer-workflow "$BUILDER"

# ------------------------------------------------------------------ evidence
if [[ -n "$ROGUE_WHL" ]]; then
  echo
  echo "=== G12 Claims vs proof on the rogue wheel"
  gh attestation verify "$ROGUE_WHL" --repo "$REPO" --format json > "$OUT/G12.json" 2>/dev/null
  {
    echo
    echo "## G12 - what the predicate CLAIMS vs what the certificate PROVES (rogue wheel)"
    echo
    echo '```'
    jq -r '.[] | "predicate claims workflow : \(.verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.path // "n/a")\ncertificate signer (SAN)  : \(.verificationResult.signature.certificate.subjectAlternativeName // "see G12.json")\n"' "$OUT/G12.json"
    echo '```'
  } >> "$REPORT"
fi

if [[ -n "$L3_WHL" ]]; then
  echo
  echo "=== G13 Independent rebuild of $TAG (reproducibility)"
  REBUILD=lab-output/rebuild
  rm -rf "$REBUILD" && git worktree add --detach "$REBUILD" "$TAG" >/dev/null 2>&1 \
    && (cd "$REBUILD" && bash scripts/build.sh >/dev/null 2>&1)
  ci_digest="$(sha256sum "$L3_WHL" | cut -d' ' -f1)"
  local_digest="$(sha256sum "$REBUILD"/dist/*.whl 2>/dev/null | cut -d' ' -f1)"
  {
    echo
    echo "## G13 - independent rebuild of $TAG"
    echo
    echo "- CI (trusted builder) digest: \`$ci_digest\`"
    echo "- Local rebuild digest:        \`${local_digest:-rebuild failed}\`"
    echo "- Identical: $([[ "$ci_digest" == "$local_digest" ]] && echo yes || echo NO)"
  } >> "$REPORT"
  git worktree remove --force "$REBUILD" >/dev/null 2>&1 || true
fi

echo
cat "$REPORT"
[[ $deviations -eq 0 ]] && echo "All executed scenarios matched the oracle." || echo "WARNING: $deviations deviation(s) - analyse them, they are findings."
