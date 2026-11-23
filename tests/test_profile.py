import unittest

from dtvn.recon.profile import get_profile


class TestScanProfile(unittest.TestCase):
    def test_get_quick_profile(self):
        profile = get_profile("quick")

        self.assertEqual(profile.name, "quick")
        self.assertEqual(profile.ports, "21,22,80,443,5432,3306")
        self.assertEqual(profile.timeout, 0.5)
        self.assertEqual(profile.workers, 5)

    def test_profile_name_is_case_insensitive(self):
        profile = get_profile("STANDARD")

        self.assertEqual(profile.name, "standard")

    def test_get_thorough_profile(self):
        profile = get_profile("thorough")

        self.assertEqual(profile.ports, "1-1024")
        self.assertEqual(profile.timeout, 1.0)
        self.assertEqual(profile.workers, 20)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            get_profile("unknown")


if __name__ == "__main__":
    unittest.main()