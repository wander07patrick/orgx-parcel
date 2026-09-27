# offline-lab

A complete SLSA Build track test drive that needs no account and no network
once `cryptography` is installed.

```bash
bash offline-lab/run_all.sh            # uses dist/*.whl, builds it if missing
bash offline-lab/run_all.sh some.file  # or any artifact you want
```

What `slsa_mini.py` does, mapped to SLSA v1.2 "Verifying artifacts":

| Step in the spec | Check in `slsa_mini.py verify` |
|------------------|--------------------------------|
| Verify the envelope signature with the roots of trust | DSSE PAE + Ed25519 against `keys/platform.pub` |
| Subject matches the artifact digest | sha256 of the file vs `subject[].digest.sha256` |
| `predicateType` is `https://slsa.dev/provenance/v1` | exact match |
| Look up the Build level (default L1) | signed by a trusted key AND `builder.id` bound to it -> that key's level, otherwise L1 |
| Compare `buildType`, source, `externalParameters` to expectations | `policy-L1.json` / `policy-L2.json`; unknown parameters fail |

`keys/platform.key` plays the build platform's signing key. It is created on
first run and git-ignored: never commit a private key, even a lab one.

Why it exists: it makes the verification logic visible (the real tools hide
it), it gives the presentation a demo that cannot fail because of the
network, and it is the fastest way to explain L1 vs L2 (scenarios O3 and O4).
