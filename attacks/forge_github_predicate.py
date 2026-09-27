#!/usr/bin/env python3
"""LAB ONLY - print a SLSA Provenance v1 predicate that lies.

It claims the wheel was built by the official workflow
(.github/workflows/l2-build-attest.yml) from tag v0.1.0, while it is really
produced by the rogue workflow. rogue-attest.yml signs it with actions/attest.

What it demonstrates: the predicate is written by whoever runs the signing
step, so it is only a claim. The fields a verifier can trust come from the
Sigstore certificate, which GitHub fills from the OIDC token (repository,
signer workflow, ref, runner type). `gh attestation verify --signer-workflow`
checks the certificate, not the predicate.
"""

import json
import os
import sys

server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
repository = os.environ.get("GITHUB_REPOSITORY", "OWNER/orgx-parcel")
commit = os.environ.get("GITHUB_SHA", "0" * 40)
run_id = os.environ.get("GITHUB_RUN_ID", "0")

predicate = {
    "buildDefinition": {
        "buildType": "https://actions.github.io/buildtypes/workflow/v1",
        "externalParameters": {
            "workflow": {
                "ref": "refs/tags/v0.1.0",
                "repository": f"{server}/{repository}",
                "path": ".github/workflows/l2-build-attest.yml",
            }
        },
        "internalParameters": {
            "github": {
                "event_name": "push",
                "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", ""),
                "repository_owner_id": os.environ.get("GITHUB_REPOSITORY_OWNER_ID", ""),
                "runner_environment": "github-hosted",
            }
        },
        "resolvedDependencies": [
            {"uri": f"git+{server}/{repository}@refs/tags/v0.1.0", "digest": {"gitCommit": commit}}
        ],
    },
    "runDetails": {
        "builder": {"id": "https://github.com/actions/runner/github-hosted"},
        "metadata": {"invocationId": f"{server}/{repository}/actions/runs/{run_id}/attempts/1"},
    },
}

json.dump(predicate, sys.stdout, indent=2)
sys.stdout.write("\n")
