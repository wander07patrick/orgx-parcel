# attacks/ - LAB ONLY

Everything in this folder simulates an adversary **against your own lab
repositories**. Never run it against a project you do not own, and never copy
the backdoor into real code.

| File | Used by | Simulates | SLSA threat (v1.2) |
|------|---------|-----------|--------------------|
| `inject_backdoor.py` | rogue workflow / rogue GitLab jobs / evil copy | a malicious source change that makes any `OX666...` parcel ID "valid" | B (modifying the source) feeding D/E |
| `forge_github_predicate.py` | `.github/workflows/rogue-attest.yml` | a SLSA predicate that *claims* the official workflow and tag | E - forge values of the provenance |
| `forge_gitlab_l1.py` | `scripts/verify-gitlab.sh` (GL2) | re-pointing an unsigned L1 statement at another artifact | E/F at Build L1 |
| `vulnerable-requirements.txt` | Part 4 of the README | known-vulnerable dependencies | dependency threats (not covered by the Build track) |

The rogue pipelines skip the unit tests on purpose: the test
`test_rejects_reserved_prefix_without_valid_check_digit` catches the backdoor.
That is a finding in itself - tests are a control, and an attacker who controls
the pipeline simply does not run them. Provenance lets the consumer detect that
the official pipeline was not the one that built the artifact.

## Dependency-threat demo (2 minutes)

```bash
python3 -m venv .venv-audit && .venv-audit/bin/pip install pip-audit
.venv-audit/bin/pip-audit --no-deps --disable-pip -r attacks/vulnerable-requirements.txt
```

Expected: dozens of known vulnerabilities reported for `requests` and `urllib3`,
while a wheel built with them would still verify perfectly against its SLSA
provenance. Record the count and the conclusion: provenance answers *how and
from what* something was built, not *whether its ingredients are safe*.
