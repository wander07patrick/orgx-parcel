# OrgX SLSA test drive - lab kit (INFO-Y-122)

This repository is the "test drive" of the SLSA framework (Supply-chain Levels
for Software Artifacts, **v1.2**) on a fictional organisation, **OrgX**, a
small logistics company that ships one Python tool (`orgx-parcel`) to its
customers. The code is deliberately tiny; the subject of the lab is the supply
chain that builds and ships it.

The lab answers four questions with evidence rather than opinions:

1. What does each SLSA Build level (L0 to L3) change in practice, on GitHub and on GitLab?
2. Which attacks from the SLSA threat model are detected at each level, and which are not?
3. How precise must the consumer's verification policy be for the levels to mean anything?
4. What does the Source track ask for, and what can our platforms actually enforce?

Every scenario has an **expected result written before it runs** (the test
oracle). A scenario that does not match its oracle is not a failure of the
lab, it is a finding to analyse.

---

## 0. Scope, ethics and anonymisation

- Run the attack simulations (`attacks/`, `rogue-*`) **only on your own lab repositories**.
- Signing with Sigstore writes your repository path, account name and
  workflow names to a **public, permanent transparency log** (Rekor). Use a
  neutral lab account and neutral names. Never use a real organisation's name,
  as required by the course for the shared knowledge base.
- OrgX, its domains (`*.orgx.example`) and its people are fictional.

## 1. Prerequisites

| Need | Why | Check |
|------|-----|-------|
| GitHub account + three **public** repositories | Artifact attestations are only available on public repositories on GitHub Free/Pro/Team | - |
| GitLab.com account, one **public** project | keyless signing with GitLab ID tokens | - |
| `git`, `python3` (3.10+), `curl`, `unzip` | build and scripts | `python3 --version` |
| GitHub CLI `gh` | download artifacts, verify attestations | `gh --version`, then `gh auth login` |
| `cosign` 2.2 or later | verify GitLab attestations | `cosign version` |

## 2. Repository map

```
.github/workflows/
  l2-build-attest.yml     L2: hosted build + signed provenance (actions/attest)
  l3-release.yml          L3: release built by the trusted builder (replace OWNER)
  rogue-attest.yml        LAB ONLY: insider/compromised-account simulation
trusted-builder-repo/     content of a SECOND repository: the trusted builder
.gitlab-ci.yml            GitLab: L1 runner provenance, keyless signing, rogue jobs
scripts/build.sh          same build everywhere: hash-pinned toolchain, reproducible
scripts/verify-github.sh  consumer-side test suite for GitHub (11 scenarios + evidence)
scripts/verify-gitlab.sh  consumer-side test suite for GitLab (8 scenarios)
offline-lab/              12 scenarios with no account at all (slsa_mini.py)
attacks/                  backdoor injector, predicate forgers, vulnerable deps
src/, tests/              the OrgX parcel-ID tool and its unit tests
RESULTS.md                template for your evidence, measurements and PDCA log
```

---

## Part A - Offline test drive (15 minutes, no account)

`offline-lab/slsa_mini.py` implements the SLSA v1.2 verification procedure in
about 300 lines: authenticity against roots of trust, subject digest,
predicate type, derived Build level, then expectations (source repository,
ref, build steps, external parameters). It uses the real formats: in-toto
Statement v1, SLSA Provenance v1 predicate, DSSE envelope, Ed25519 signature.

```bash
bash scripts/build.sh           # L0: a local build, nothing a consumer can verify
bash offline-lab/run_all.sh     # 12 scenarios, report in lab-output/offline-results.md
```

Expected (all 12 must match the oracle):

| ID | Threat | Scenario | Expected |
|----|--------|----------|----------|
| O1 | - | L1 legitimate unsigned provenance | PASS |
| O2 | F | L1, artifact tampered after the build | FAIL |
| O3 | D/E | L1, **forged** provenance for a backdoored artifact | **PASS** (L1 is forgeable) |
| O4 | D/E | same forgery, consumer demands L2 | FAIL |
| O5 | - | L2 legitimate platform-signed provenance | PASS |
| O6 | F | L2, provenance edited after signing | FAIL |
| O7 | E | L2, provenance signed with an attacker's key | FAIL |
| O8 | D | built from an unofficial fork | FAIL |
| O9 | D | built from an unofficial branch | FAIL |
| O10 | D | built with unofficial build steps | FAIL |
| O11 | D | unofficial external parameter injected | FAIL |
| O12 | F | L2, artifact tampered after the build | FAIL |

O3 vs O4 is the core lesson of Build L1 vs L2. Keep this run as your
presentation fallback if the network fails.

---

## Part B - GitHub, from L0 to L3

### B1. Create the repositories (public)

| Repository | Content |
|------------|---------|
| `orgx-parcel` | this whole folder except `trusted-builder-repo/` |
| `orgx-trusted-builder` | the content of `trusted-builder-repo/` |
| `orgx-parcel-evil` | a copy of `orgx-parcel` with the backdoor (step B5) |

```bash
# in this folder
git init -b main && git add . && git commit -m "OrgX lab: initial import"
git remote add origin https://github.com/OWNER/orgx-parcel.git
git push -u origin main
```

### B2. Build L2 - hosted build with signed provenance

The push to `main` runs **L2 build and attest**. Then:

- open *Actions > L2 build and attest > the run*: in the "Build" step log,
  copy the line starting with `[lab probe]`. It should say the build steps
  **CAN** obtain an OIDC signing identity: the build and the signature share
  one job, which is why this is L2 and not L3;
- open the repository's *Attestations* page (link in the run summary) and
  take a screenshot;
- verify it yourself:

```bash
gh run download -R OWNER/orgx-parcel -n orgx-parcel-dist -D lab-output/l2
gh attestation verify lab-output/l2/*.whl --repo OWNER/orgx-parcel
gh attestation verify lab-output/l2/*.whl --repo OWNER/orgx-parcel --format json \
  --jq '.[].verificationResult.statement.predicate' > lab-output/l2-predicate.json
```

Read `l2-predicate.json` against the SLSA provenance model:
`buildDefinition.buildType`, `externalParameters`, `resolvedDependencies`,
`runDetails.builder.id`.

### B3. Build L3 - the trusted builder

1. Create `orgx-trusted-builder` as explained in `trusted-builder-repo/README.md`
   (workflow on `main`, tag `v1`, rulesets on `main` and `v*`).
2. In `orgx-parcel`, replace the placeholder and release:

```bash
sed -i.bak "s/OWNER/<your-account>/" .github/workflows/l3-release.yml && rm .github/workflows/l3-release.yml.bak
git commit -am "Use the trusted builder for releases" && git push
git tag v0.1.0 && git push origin v0.1.0     # triggers "L3 release (trusted builder)"
```

3. In the run, open the **build** job: the `[lab probe]` line must now say the
   build steps can **NOT** obtain a signing identity. The signature happens in
   the separate **provenance** job, which runs none of your code. This is the
   evidence for the L3 requirements "Provenance is Unforgeable" and "Isolated".

### B4. Why the order of the next steps matters

Attestations are attached to **digests**, not to files. `scripts/build.sh` is
reproducible: two builds of the same commit produce the same bytes, therefore
the same digest, therefore they share each other's attestations. To keep the
scenarios meaningful, every "different" artifact below comes from a different
commit. Write this observation in your analysis: it is a real property of
provenance systems, not a bug of the lab.

### B5. Attack: a backdoored copy in another repository (threat D)

```bash
git clone https://github.com/OWNER/orgx-parcel.git orgx-parcel-evil && cd orgx-parcel-evil
python3 attacks/inject_backdoor.py && git commit -am "totally harmless change"
git remote set-url origin https://github.com/OWNER/orgx-parcel-evil.git && git push -u origin main
cd ..
```

(Create the empty `orgx-parcel-evil` repository on GitHub first. Its L2
workflow will build and attest the backdoored wheel.)

### B6. Attack: rogue workflow inside the official repository (threats D/E)

*Actions > "LAB ONLY - rogue attestation" > Run workflow* (or
`gh workflow run rogue-attest.yml -R OWNER/orgx-parcel`). It produces a
backdoored wheel with the same name and version as the real one, plus two
attestations: one honest (names the rogue workflow), one with a forged predicate.

### B7. Attack: build from an unofficial branch (threat D)

```bash
git switch -c experimental
echo "# experimental" >> src/orgx_parcel/cli.py && git commit -am "experimental change" && git push -u origin experimental
gh workflow run l2-build-attest.yml -R OWNER/orgx-parcel --ref experimental
git switch main
```

### B8. One more commit on main (unreleased)

```bash
git commit --allow-empty -m "post-release commit" && git push
```

This produces an L2 wheel that the trusted builder never built (scenario G10).

### B9. Run the consumer test suite

```bash
OWNER=<your-account> bash scripts/verify-github.sh
```

It downloads all artifacts, runs 11 verification scenarios with their oracle,
extracts the "claims vs proof" evidence on the rogue wheel (G12) and rebuilds
`v0.1.0` locally to compare digests (G13). Output: `lab-output/github-results.md`.

| ID | Threat | Scenario | Policy | Expected |
|----|--------|----------|--------|----------|
| G1 | - | L2 official wheel | `--repo` | PASS |
| G2 | - | L2 official wheel | `--repo --signer-workflow l2` | PASS |
| G3 | F | wheel modified after build | `--repo` | FAIL |
| G4 | D | evil copy's wheel | `--repo` | FAIL |
| G5 | D | evil copy's wheel | `--owner` only | **PASS** (policy too loose) |
| G6 | D/E | rogue wheel | `--repo` only | **PASS** (policy too loose) |
| G7 | D/E | rogue wheel | `--repo --signer-workflow l2` | FAIL |
| G8 | D | branch wheel | `--source-ref refs/heads/main` | FAIL |
| G9 | - | release by trusted builder | L3 policy | PASS |
| G10 | E | L2 wheel of unreleased commit | L3 policy | FAIL |
| G11 | D/E | rogue wheel | L3 policy | FAIL |

The L3 policy is `--repo OWNER/orgx-parcel --signer-workflow
OWNER/orgx-trusted-builder/.github/workflows/build-python-wheel.yml --source-ref
refs/tags/v0.1.0 --deny-self-hosted-runners`.

G12 is the most important slide of the presentation: the rogue predicate
*claims* the official workflow, the certificate *proves* the rogue one. Only
certificate fields (filled by GitHub from the OIDC token) are evidence; the
predicate is whatever the signer wrote.

---

## Part C - GitLab

### C1. Create the project and run the pipeline

Create a **public** project `orgx-parcel` in an anonymous namespace, push the
same code (`git remote add gitlab https://gitlab.com/<namespace>/orgx-parcel.git && git push gitlab main`).
The pipeline runs `test > build > attest > verify`.

- **L1**: the `build` job sets `RUNNER_GENERATE_ARTIFACTS_METADATA`; the runner
  writes an unsigned SLSA provenance next to the artifacts. The `attest` job
  prints its header and keeps it as `runner-provenance.json`.
- **Signed**: the `attest` job signs that provenance with `cosign attest-blob`
  using a GitLab ID token (keyless Sigstore); `verify` checks it in-pipeline.
- Note the `[lab probe]` line of the `build` job (no ID token there).

### C2. Rogue jobs

Play `rogue-build`, then `rogue-attest` (manual jobs). They sign the genuine
predicate over a backdoored wheel from the same pipeline file.

### C3. GitLab's own L3

GitLab documents "SLSA level 3 provenance attestations" as an **Experiment**,
for the **Ultimate** tier, behind a feature flag that is off by default, for
public projects only. Check your project's *Build > Attestations* menu and
record what you observe. Do not simulate it: an honest "not available on our
tier" is a valid result and a finding about platform choice.

### C4. Consumer test suite

```bash
GL_PROJECT=<namespace>/orgx-parcel bash scripts/verify-gitlab.sh
```

| ID | Threat | Scenario | Expected |
|----|--------|----------|----------|
| GL1 | - | runner provenance exists, unsigned | info |
| GL2 | D/E | L1 statement re-pointed at the backdoored wheel | forgery undetectable |
| GL3 | - | official wheel + official signed attestation | PASS |
| GL4 | F | wheel modified after signing | FAIL |
| GL5 | D | consumer expects another branch | FAIL |
| GL6 | F | backdoored wheel with the official bundle | FAIL |
| GL7 | D/E | backdoored wheel signed by the rogue job | **PASS** |
| GL8 | - | GitLab L3 attestation | record availability |

GL7 is the GitLab counterpart of G6/G12: the certificate identity is
`https://gitlab.com/<namespace>/orgx-parcel//.gitlab-ci.yml@refs/heads/main`,
i.e. the **pipeline file**, not the job, so any job in that file can sign.
Discuss whether the in-pipeline signing meets "Provenance is Authentic" (the
provenance must be generated by the control plane, not by a tenant) and
compare with GitHub's reusable-workflow identity.

---

## Part D - Source track checks (v1.2, levels 1 to 4)

Configure, try to break, record. Screenshots of the rejection messages are
your evidence.

| Control | GitHub (Settings > Rules > Rulesets) | GitLab (Settings > Repository) | Try this | Expected | Source level |
|---------|-----------|--------|----------|----------|--------------|
| Version control, stable IDs | built in | built in | - | - | L1 |
| No history rewrite on `main` | block force pushes | protected branch, force push off | `git push --force` of a rewritten `main` | rejected | L2 |
| `main` cannot be deleted | restrict deletions | protected branch | `git push origin :main` | rejected | L2 |
| Release tags immutable | tag ruleset `v*`: restrict updates and deletions | protected tags `v*` | move `v0.1.0` and force-push it | rejected | L2 |
| Source provenance issued by the platform | not native: evaluate `slsa-framework/source-tool` | not native | look for it, document | gap | L2 requirement |
| Checks enforced before merge | require PR + status check `build-and-attest` | "Pipelines must succeed" | push directly to `main` | rejected | L3 |
| Two-party review | require 1 approval, dismiss stale approvals | approval rules (check your tier) | merge without approval; push after approval | blocked; approval reset | L4 |

Working alone, you cannot demonstrate L4 without a second trusted person:
invite a classmate as collaborator and reviewer, or record the limitation.

---

## Part E - Dependency threat (2 minutes)

See `attacks/README.md`. Expected: many known vulnerabilities reported by
`pip-audit`, while provenance of a wheel built with them would verify. The
Build track does not judge ingredients; that is the job of SCA tools today and
of the future SLSA Dependency track (built on S2C2F).

## Part F - Measurements to record (fill `RESULTS.md`)

| ID | Metric | How |
|----|--------|-----|
| M1 | Set-up time per level (min) | pomodoro log |
| M2 | Pipeline duration per workflow (s) | CI run page |
| M3 | Duration of the attest/sign step (s) | job log timestamps |
| M4 | Verification time per scenario (s) | column in `github-results.md` |
| M5 | Lines of pipeline YAML per level | `wc -l` on the workflow files |
| M6 | Manual steps per level | count them in this README |
| M7 | Third-party actions/images in the pipeline | read the YAML |
| M8 | Reproducible rebuild (same digest) | G13 |
| M9 | Scenarios matching the oracle / executed | the three reports |

## Part G - Clean-up

```bash
gh workflow disable rogue-attest.yml -R OWNER/orgx-parcel
gh repo delete OWNER/orgx-parcel-evil
```

Disable the GitLab rogue jobs (delete them from `.gitlab-ci.yml`), archive the
repositories when the course is over, and revoke any token you created.
Transparency-log entries cannot be deleted - which is why anonymisation comes first.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| "Feature not available ... make this repository public" | attestations need a public repository on GitHub Free |
| "Unable to get ACTIONS_ID_TOKEN_REQUEST_URL" | the job lacks `id-token: write` |
| Reusable workflow not found | `OWNER` not replaced, builder repository private, or tag `v1` missing |
| `gh attestation verify`: no attestations found for a genuine wheel | you verified a local rebuild of another commit, or the wrong `--repo` |
| GitLab: "none of the expected identities matched" | the identity needs the double slash `project//.gitlab-ci.yml@refs/heads/main` |
| GitLab: runner provenance not found | record it; inspect the build job's artifact archive by hand |
| cosign cannot read the bundle | use the same cosign major version as the pipeline (see `cosign version` in the job log) |

## Scenario-to-requirement map (SLSA v1.2)

| Requirement or threat | Scenarios |
|-----------------------|-----------|
| Provenance Exists (Build L1) | O1, B2, GL1 |
| Provenance is Authentic (Build L2) | O4-O7, G1-G3, GL3-GL4 |
| Provenance is Unforgeable, Isolated (Build L3) | `[lab probe]` L2 vs L3, G9-G11, GL7 |
| Hosted (Build L2) | L0 local build vs CI runs |
| Verification: expectations on source, ref, build steps, parameters | O8-O11, G4-G8, GL5 |
| (F) Artifact publication / tampering | O2, O12, G3, GL4, GL6 |
| (E) Forge values of the provenance | O3, O7, G6-G7, G11-G12, GL2, GL7 |
| Source track L1-L4 | Part D |
| Dependency threats (out of scope of the Build track) | Part E |
