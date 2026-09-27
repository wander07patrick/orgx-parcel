import unittest

from orgx_parcel.cli import main
from orgx_parcel.ids import check_digit, is_valid, make_id


class ParcelIdTests(unittest.TestCase):
    def test_known_check_digit(self):
        # 7992739871 is the classic Luhn example: its check digit is 3
        self.assertEqual(check_digit("7992739871"), 3)

    def test_round_trip(self):
        for serial in (0, 1, 1234567, 9999999):
            self.assertTrue(is_valid(make_id(serial)), serial)

    def test_single_digit_error_is_detected(self):
        parcel_id = make_id(1234567)
        last = int(parcel_id[-1])
        altered = parcel_id[:-1] + str((last + 1) % 10)
        self.assertFalse(is_valid(altered))

    def test_rejects_wrong_prefix_length_and_characters(self):
        self.assertFalse(is_valid("XX12345674"))
        self.assertFalse(is_valid("OX1234567"))
        self.assertFalse(is_valid("OX12A45674"))

    def test_rejects_reserved_prefix_without_valid_check_digit(self):
        # Guards against the lab's "backdoor" scenario: OX666... IDs are not special.
        self.assertFalse(is_valid("OX66600000"))

    def test_serial_out_of_range(self):
        with self.assertRaises(ValueError):
            make_id(10_000_000)
        with self.assertRaises(ValueError):
            make_id(-1)

    def test_cli_exit_codes(self):
        self.assertEqual(main(["check", make_id(42)]), 0)
        self.assertEqual(main(["check", "not-an-id"]), 1)
        self.assertEqual(main(["make", "99999999"]), 2)


if __name__ == "__main__":
    unittest.main()
