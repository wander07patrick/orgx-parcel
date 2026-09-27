#!/usr/bin/env python3
"""slsa_mini.py - a teaching-size SLSA provenance generator, signer and verifier.

It implements, in ~300 readable lines, the verification procedure of
SLSA v1.2 "Build: Verifying artifacts" (https://slsa.dev/spec/v1.2/verifying-artifacts):

  Step 1  check the provenance's authenticity against pre-configured roots of
          trust, check that its subject digest matches the artifact, check the
          predicateType, and derive the SLSA Build level (default L1);
  Step 2  compare buildType / externalParameters / source against expectations.

Formats follow the real ones: an in-toto Statement v1 carrying a SLSA
Provenance v1 predicate, wrapped in a DSSE envelope signed with Ed25519.
Everything runs offline, so the lab can be demonstrated without any account.

Usage (see run_all.sh for the full scenario list):
  python slsa_mini.py keygen    --out keys/platform
  python slsa_mini.py provenance ARTIFACT --builder-id URI --repo URI --ref REF \
                                 --workflow PATH --commit SHA [--param k=v] --out stmt.json
  python slsa_mini.py sign      stmt.json --key keys/platform.key --out envelope.json
  python slsa_mini.py verify    ARTIFACT PROVENANCE --policy policy.json
"""

import argparse
import base64
import datetime as dt
import fnmatch
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
BUILD_TYPE = "https://orgx.example/buildtypes/python-wheel/v1"


# --------------------------------------------------------------------------- helpers
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding."""
    type_bytes = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(type_bytes), type_bytes, len(payload), payload)


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- commands
def cmd_keygen(args) -> int:
    private_key = Ed25519PrivateKey.generate()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".key").write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    out.with_suffix(".pub").write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"key pair written: {out.with_suffix('.key')} / {out.with_suffix('.pub')}")
    return 0


def cmd_provenance(args) -> int:
    artifact = Path(args.artifact)
    external = {"repository": args.repo, "ref": args.ref, "workflow": args.workflow}
    for item in args.param or []:
        name, _, value = item.partition("=")
        external[name] = value
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": artifact.name, "digest": {"sha256": sha256_file(artifact)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": args.build_type,
                "externalParameters": external,
                "internalParameters": {"runnerImage": "python:3.12-slim"},
                "resolvedDependencies": [
                    {"uri": f"{args.repo}@{args.ref}", "digest": {"gitCommit": args.commit}}
                ],
            },
            "runDetails": {
                "builder": {"id": args.builder_id},
                "metadata": {"invocationId": args.invocation_id, "startedOn": now_utc(), "finishedOn": now_utc()},
            },
        },
    }
    Path(args.out).write_text(json.dumps(statement, indent=2) + "\n")
    print(f"unsigned provenance written: {args.out}")
    return 0


def cmd_sign(args) -> int:
    private_key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    payload = Path(args.statement).read_bytes()
    signature = private_key.sign(pae(DSSE_PAYLOAD_TYPE, payload))
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": key_id(private_key.public_key()), "sig": base64.b64encode(signature).decode()}],
    }
    Path(args.out).write_text(json.dumps(envelope, indent=2) + "\n")
    print(f"DSSE envelope written: {args.out}")
    return 0


# --------------------------------------------------------------------------- verify
class Report:
    def __init__(self):
        self.rows = []

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        self.rows.append(("ok  " if ok else "FAIL", label, detail))
        return ok

    def info(self, label: str, detail: str = "") -> None:
        self.rows.append(("info", label, detail))

    def passed(self) -> bool:
        return all(mark != "FAIL" for mark, _, _ in self.rows)

    def print(self):
        for mark, label, detail in self.rows:
            print(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""))


def cmd_verify(args) -> int:
    policy_path = Path(args.policy)
    policy = json.loads(policy_path.read_text())
    expect = policy["expectations"]
    report = Report()
    level = 0

    document = json.loads(Path(args.provenance).read_text())

    # ---- Step 1a: authenticity (envelope signature vs roots of trust) ----------
    trusted_root = None
    if "payloadType" in document:  # DSSE envelope
        payload = base64.b64decode(document["payload"])
        known_key_ids = set()
        for root in policy["roots_of_trust"]:
            public_key = load_public_key(policy_path.parent / root["public_key"])
            known_key_ids.add(key_id(public_key))
            for sig in document.get("signatures", []):
                try:
                    public_key.verify(base64.b64decode(sig["sig"]), pae(document["payloadType"], payload))
                    trusted_root = root
                except InvalidSignature:
                    continue
        if trusted_root:
            reason = "signer recognised"
        elif any(sig.get("keyid") in known_key_ids for sig in document.get("signatures", [])):
            reason = "trusted key id, but the payload was modified after signing"
        else:
            reason = "signed by a key that is not in the roots of trust"
        if not report.check("Envelope signature made by a key in the roots of trust", trusted_root is not None, reason):
            report.print()
            print("RESULT: FAIL")
            return 1
        statement = json.loads(payload)
    else:
        report.info("Envelope signature", "none: unsigned statement, authenticity NOT established")
        statement = document

    # ---- Step 1b: subject digest and predicate type ----------------------------
    actual = sha256_file(Path(args.artifact))
    digests = [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]
    report.check("Subject digest matches the artifact", actual in digests, f"artifact sha256 {actual[:16]}...")
    report.check("predicateType is SLSA Provenance v1", statement.get("predicateType") == PREDICATE_TYPE)

    predicate = statement.get("predicate", {})
    build = predicate.get("buildDefinition", {})
    builder_id = predicate.get("runDetails", {}).get("builder", {}).get("id")

    # ---- Step 1c: derive the SLSA Build level ----------------------------------
    if trusted_root and trusted_root["builder_id"] == builder_id:
        level = trusted_root["max_level"]
        report.check("builder.id bound to the recognised key", True, builder_id)
    elif trusted_root:
        level = 1
        report.check("builder.id bound to the recognised key", False, f"{builder_id} is not {trusted_root['builder_id']}")
    else:
        level = 1  # spec: default to SLSA Build L1 when nothing authenticates the builder
    report.check(f"SLSA Build level >= {policy['min_level']} (derived: L{level})", level >= policy["min_level"])

    # ---- Step 2: expectations --------------------------------------------------
    external = build.get("externalParameters", {})
    report.check("buildType matches expectation", build.get("buildType") == expect["buildType"], build.get("buildType"))
    report.check(
        "Source repository matches expectation",
        external.get("repository") == expect["source_repository"],
        external.get("repository"),
    )
    ref = external.get("ref", "")
    report.check(
        "Source ref is an allowed branch/tag",
        any(fnmatch.fnmatch(ref, pattern) for pattern in expect["allowed_refs"]),
        ref,
    )
    report.check("Build steps (workflow) match expectation", external.get("workflow") == expect["workflow"], external.get("workflow"))
    unknown = sorted(set(external) - set(expect["externalParameters_allowed_keys"]))
    report.check("No unrecognised externalParameters", not unknown, ", ".join(unknown) if unknown else "")

    report.print()
    passed = report.passed()
    print("RESULT: PASS" if passed else "RESULT: FAIL")
    return 0 if passed else 1


# --------------------------------------------------------------------------- main
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("provenance")
    p.add_argument("artifact")
    p.add_argument("--builder-id", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--ref", required=True)
    p.add_argument("--workflow", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--build-type", default=BUILD_TYPE)
    p.add_argument("--invocation-id", default="https://ci.orgx.example/jobs/1")
    p.add_argument("--param", action="append", help="extra external parameter k=v")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_provenance)

    p = sub.add_parser("sign")
    p.add_argument("statement")
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify")
    p.add_argument("artifact")
    p.add_argument("provenance")
    p.add_argument("--policy", required=True)
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
