import unittest
from dtvn.recon.target import is_valid_hostname, is_valid_ipv4, validate_target


class TestTargetValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ipv4("127.0.0.1"))
        self.assertTrue(is_valid_ipv4("192.168.1.10"))
        info = validate_target("127.0.0.1")
        self.assertEqual(info.target_type, "ipv4")

    def test_invalid_ipv4(self):
        self.assertFalse(is_valid_ipv4("127.0.0.999"))
        self.assertFalse(is_valid_ipv4("256.1.1.1"))

    def test_valid_hostname(self):
        self.assertTrue(is_valid_hostname("localhost"))
        self.assertTrue(is_valid_hostname("lab-server.local"))
        info = validate_target("localhost")
        self.assertEqual(info.target_type, "hostname")

    def test_rejects_malformed_and_injection_inputs(self):
        invalid_targets = ["", "   ", "127.0.0.999", "127.0.0.1; whoami", "-invalid.host"]
        for bad in invalid_targets:
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    validate_target(bad)


if __name__ == "__main__":
    unittest.main()