#!/usr/bin/env bash
# Offline SLSA test drive: 12 scenarios mapped to the SLSA v1.2 threat model.
# Each scenario has an EXPECTED result (the test oracle); the script reports
# whether reality matched it. No account, no network needed after setup.
#
#   bash offline-lab/run_all.sh [path/to/artifact]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$HERE" || exit 1

# ---------------------------------------------------------------- setup
if [[ ! -x .venv-offline/bin/python ]]; then
  python3 -m venv .venv-offline
  .venv-offline/bin/python -m pip install --quiet --disable-pip-version-check "cryptography>=42"
fi
PY=".venv-offline/bin/python"
MINI="$PY slsa_mini.py"

ARTIFACT="${1:-}"
if [[ -z "$ARTIFACT" ]]; then
  ARTIFACT="$(ls "$ROOT"/dist/*.whl 2>/dev/null | head -n1 || true)"
  if [[ -z "$ARTIFACT" ]]; then
    echo "No wheel found, building one with scripts/build.sh ..."
    bash "$ROOT/scripts/build.sh" >/dev/null
    ARTIFACT="$(ls "$ROOT"/dist/*.whl | head -n1)"
  fi
fi

WORK="$HERE/work"
rm -rf "$WORK" && mkdir -p "$WORK" keys
[[ -f keys/platform.key ]] || $MINI keygen --out keys/platform >/dev/null   # the build platform's key
$MINI keygen --out "$WORK/attacker" >/dev/null                              # an attacker's own key

cp "$ARTIFACT" "$WORK/official.whl"
cp "$ARTIFACT" "$WORK/evil.whl" && printf 'backdoor' >> "$WORK/evil.whl"      # attacker's artifact

REPO="git+https://git.orgx.example/orgx/parcel"
BUILDER="https://ci.orgx.example/runners/hosted"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo 0000000000000000000000000000000000000000)"

prov() { # prov <artifact> <out> [--repo X] [--ref Y] [--workflow Z] [--param k=v]
  local artifact="$1" out="$2"; shift 2
  local repo="$REPO" ref="refs/heads/main" workflow=".ci/release.yml" extra=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) repo="$2"; shift 2 ;;
      --ref) ref="$2"; shift 2 ;;
      --workflow) workflow="$2"; shift 2 ;;
      --param) extra+=(--param "$2"); shift 2 ;;
      *) shift ;;
    esac
  done
  $MINI provenance "$artifact" --builder-id "$BUILDER" --repo "$repo" --ref "$ref" \
    --workflow "$workflow" --commit "$COMMIT" "${extra[@]}" --out "$out" >/dev/null
}
sign() { $MINI sign "$1" --key "$2" --out "$3" >/dev/null; }

# ---------------------------------------------------------------- provenance fixtures
prov "$WORK/official.whl" "$WORK/official.stmt.json"
sign "$WORK/official.stmt.json" keys/platform.key "$WORK/official.dsse.json"

prov "$WORK/evil.whl" "$WORK/forged.stmt.json"                          # claims the official source!
sign "$WORK/forged.stmt.json" "$WORK/attacker.key" "$WORK/forged-attacker.dsse.json"

prov "$WORK/evil.whl" "$WORK/fork.stmt.json" --repo "git+https://git.evil.example/fork/parcel"
sign "$WORK/fork.stmt.json" keys/platform.key "$WORK/fork.dsse.json"

prov "$WORK/evil.whl" "$WORK/branch.stmt.json" --ref "refs/heads/experimental"
sign "$WORK/branch.stmt.json" keys/platform.key "$WORK/branch.dsse.json"

prov "$WORK/evil.whl" "$WORK/steps.stmt.json" --workflow ".ci/debug.yml"
sign "$WORK/steps.stmt.json" keys/platform.key "$WORK/steps.dsse.json"

prov "$WORK/evil.whl" "$WORK/param.stmt.json" --param "compilerFlags=-DSKIP_AUTH"
sign "$WORK/param.stmt.json" keys/platform.key "$WORK/param.dsse.json"

# provenance tampered AFTER signing: rewrite the ref inside the signed payload
$PY - "$WORK/official.dsse.json" "$WORK/tampered.dsse.json" <<'EOF'
import base64, json, sys
env = json.load(open(sys.argv[1]))
stmt = json.loads(base64.b64decode(env["payload"]))
stmt["predicate"]["buildDefinition"]["externalParameters"]["ref"] = "refs/tags/v9.9.9"
env["payload"] = base64.b64encode(json.dumps(stmt).encode()).decode()
json.dump(env, open(sys.argv[2], "w"), indent=2)
EOF

# ---------------------------------------------------------------- scenarios
# id | threat | description | artifact | provenance | policy | expected
SCENARIOS=(
  "O1|-|L1: legitimate unsigned provenance|official.whl|official.stmt.json|policy-L1.json|PASS"
  "O2|F|L1: artifact tampered after the build|evil.whl|official.stmt.json|policy-L1.json|FAIL"
  "O3|D/E|L1: forged unsigned provenance for a backdoored artifact|evil.whl|forged.stmt.json|policy-L1.json|PASS"
  "O4|D/E|Same forgery, consumer demands L2|evil.whl|forged.stmt.json|policy-L2.json|FAIL"
  "O5|-|L2: legitimate platform-signed provenance|official.whl|official.dsse.json|policy-L2.json|PASS"
  "O6|F|L2: provenance edited after signing|official.whl|tampered.dsse.json|policy-L2.json|FAIL"
  "O7|E|L2: provenance signed with the attacker's own key|evil.whl|forged-attacker.dsse.json|policy-L2.json|FAIL"
  "O8|D|L2: built from an unofficial fork|evil.whl|fork.dsse.json|policy-L2.json|FAIL"
  "O9|D|L2: built from an unofficial branch|evil.whl|branch.dsse.json|policy-L2.json|FAIL"
  "O10|D|L2: built with unofficial build steps|evil.whl|steps.dsse.json|policy-L2.json|FAIL"
  "O11|D|L2: unofficial external parameter injected|evil.whl|param.dsse.json|policy-L2.json|FAIL"
  "O12|F|L2: artifact tampered after the build|evil.whl|official.dsse.json|policy-L2.json|FAIL"
)

mkdir -p "$ROOT/lab-output"
REPORT="$ROOT/lab-output/offline-results.md"
{
  echo "# Offline SLSA test drive - results"
  echo
  echo "Artifact: \`$(basename "$ARTIFACT")\` (sha256 \`$(sha256sum "$ARTIFACT" | cut -c1-16)...\`), run on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| ID | SLSA threat | Scenario | Expected | Observed | Matches oracle |"
  echo "|----|-------------|----------|----------|----------|----------------|"
} > "$REPORT"

deviations=0
for row in "${SCENARIOS[@]}"; do
  IFS='|' read -r id threat desc artifact provenance policy expected <<<"$row"
  echo
  echo "=== $id [$threat] $desc  (expected: $expected)"
  if $MINI verify "$WORK/$artifact" "$WORK/$provenance" --policy "$policy"; then observed="PASS"; else observed="FAIL"; fi
  if [[ "$observed" == "$expected" ]]; then match="yes"; else match="NO"; deviations=$((deviations + 1)); fi
  echo "| $id | $threat | $desc | $expected | $observed | $match |" >> "$REPORT"
done

echo
echo "Report written to $REPORT"
cat "$REPORT"
if [[ $deviations -gt 0 ]]; then
  echo "WARNING: $deviations scenario(s) did not match the oracle - investigate before presenting."
  exit 1
fi
echo "All scenarios matched the expected outcome."
