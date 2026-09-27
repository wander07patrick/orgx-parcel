# Offline SLSA test drive - results

Artifact: `orgx_parcel-0.1.0-py3-none-any.whl` (sha256 `0dc2aab87d0e4475...`), run on 2026-09-27T14:43:52Z

| ID | SLSA threat | Scenario | Expected | Observed | Matches oracle |
|----|-------------|----------|----------|----------|----------------|
| O1 | - | L1: legitimate unsigned provenance | PASS | PASS | yes |
| O2 | F | L1: artifact tampered after the build | FAIL | FAIL | yes |
| O3 | D/E | L1: forged unsigned provenance for a backdoored artifact | PASS | PASS | yes |
| O4 | D/E | Same forgery, consumer demands L2 | FAIL | FAIL | yes |
| O5 | - | L2: legitimate platform-signed provenance | PASS | PASS | yes |
| O6 | F | L2: provenance edited after signing | FAIL | FAIL | yes |
| O7 | E | L2: provenance signed with the attacker's own key | FAIL | FAIL | yes |
| O8 | D | L2: built from an unofficial fork | FAIL | FAIL | yes |
| O9 | D | L2: built from an unofficial branch | FAIL | FAIL | yes |
| O10 | D | L2: built with unofficial build steps | FAIL | FAIL | yes |
| O11 | D | L2: unofficial external parameter injected | FAIL | FAIL | yes |
| O12 | F | L2: artifact tampered after the build | FAIL | FAIL | yes |
