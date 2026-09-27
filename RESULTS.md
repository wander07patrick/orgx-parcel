# RESULTS - OrgX SLSA test drive

> Fill this file with YOUR runs. Paste the generated reports, add the
> screenshots to `evidence/`, and sign the bottom of the file. Delete the
> guidance lines in italics when done.

## 1. Environment

| Item | Value |
|------|-------|
| Date(s) of the runs | |
| Operator | |
| GitHub repositories (anonymised names) | |
| GitLab project (anonymised path) | |
| `gh --version` | |
| `cosign version` (laptop / pipeline) | |
| Python version (laptop) | |
| Commit tested / release tag | |

## 2. Hypotheses (written BEFORE the runs)

| ID | Hypothesis | Test | Supported? |
|----|-----------|------|------------|
| H1 | Unsigned (L1) provenance can be forged and still pass a policy that only asks for L1. | O3, GL2 | |
| H2 | Signed provenance (L2) detects any modification of the artifact or of the provenance after the build. | O6, O12, G3, GL4 | |
| H3 | A policy that pins only the repository (or the owner) accepts artifacts built by unofficial build steps. | G5, G6, GL7 | |
| H4 | Pinning the signer workflow of a trusted builder (L3) rejects them. | G7, G11 | |
| H5 | In the L3 set-up, user-defined build steps cannot obtain the signing identity. | `[lab probe]` lines | |
| H6 | Provenance does not reveal vulnerable dependencies. | Part E | |
| H7 | The build is reproducible: an independent rebuild gives the same digest. | G13 | |

## 3. Results

### 3.1 Offline (paste `lab-output/offline-results.md`)

### 3.2 GitHub (paste `lab-output/github-results.md`)

`[lab probe]` line, L2 job: ...

`[lab probe]` line, L3 build job: ...

### 3.3 GitLab (paste `lab-output/gitlab-results.md`)

`[lab probe]` line, build job: ...

GitLab L3 attestation availability (tier, feature flag, what you saw): ...

### 3.4 Source track checks

| Control | Platform | Configured how | Attempt | Observed | Evidence file |
|---------|----------|----------------|---------|----------|---------------|
| Block force push on main | GitHub | | | | |
| Block force push on main | GitLab | | | | |
| Protected release tags | GitHub | | | | |
| Protected release tags | GitLab | | | | |
| Checks required before merge | GitHub | | | | |
| Checks required before merge | GitLab | | | | |
| Two-party review | GitHub | | | | |
| Two-party review | GitLab | | | | |
| Source provenance / Source VSA | both | | | | |

### 3.5 Dependency threat

Number of vulnerabilities reported by `pip-audit`: ... Conclusion: ...

## 4. Measurements

| ID | Metric | L0 | L1 | L2 | L3 | GitLab | Notes |
|----|--------|----|----|----|----|--------|-------|
| M1 | Set-up time (min) | | | | | | |
| M2 | Pipeline duration (s) | | | | | | |
| M3 | Attest/sign step (s) | | | | | | |
| M4 | Verification time (s) | | | | | | |
| M5 | Pipeline YAML lines | | | | | | |
| M6 | Manual steps | | | | | | |
| M7 | Third-party actions / images | | | | | | |
| M8 | Reproducible rebuild | | | | | | |
| M9 | Scenarios matching oracle | | | | | | |

## 5. Failures and adjustments log (one PDCA per problem)

| # | Date | Plan (what we tried) | Do (what happened) | Check (why) | Act (what we changed) | Time lost (pomodoros) |
|---|------|----------------------|--------------------|-------------|-----------------------|-----------------------|
| 1 | | | | | | |

## 6. Conclusions

*What each level bought OrgX, what it cost, which threats remain, what you recommend.*

## 7. Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Author (operator of the runs) | | | |
| Reviewer | | | |
