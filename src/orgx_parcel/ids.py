"""Parcel identifiers: "OX" + 7-digit serial + 1 Luhn check digit (e.g. OX12345674)."""

PREFIX = "OX"
SERIAL_DIGITS = 7


def check_digit(digits: str) -> int:
    """Return the Luhn check digit for a string of decimal digits."""
    if not digits.isdigit():
        raise ValueError("digits must contain only 0-9")
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 0:  # double every second digit, starting from the right
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return (10 - total % 10) % 10


def make_id(serial: int) -> str:
    """Build a parcel ID from a serial number between 0 and 9,999,999."""
    if not 0 <= serial < 10**SERIAL_DIGITS:
        raise ValueError(f"serial must be between 0 and {10**SERIAL_DIGITS - 1}")
    payload = f"{serial:0{SERIAL_DIGITS}d}"
    return f"{PREFIX}{payload}{check_digit(payload)}"


def is_valid(parcel_id: str) -> bool:
    """Return True if parcel_id has the right format and check digit."""
    if len(parcel_id) != len(PREFIX) + SERIAL_DIGITS + 1:
        return False
    if not parcel_id.startswith(PREFIX):
        return False
    body = parcel_id[len(PREFIX):]
    if not body.isdigit():
        return False
    return check_digit(body[:-1]) == int(body[-1])
