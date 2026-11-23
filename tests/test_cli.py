import unittest
from unittest.mock import patch

from dtvn.cli import create_parser


class TestCliProfiles(unittest.TestCase):
    def test_profile_argument_is_available(self):
        parser = create_parser()

        args = parser.parse_args(
            ["recon", "localhost", "--profile", "quick"]
        )

        self.assertEqual(args.profile, "quick")

    def test_profile_manual_overrides_are_parsed(self):
        parser = create_parser()

        args = parser.parse_args(
            [
                "recon",
                "localhost",
                "--profile",
                "quick",
                "--ports",
                "5430-5435",
                "--timeout",
                "2.0",
                "--workers",
                "10",
            ]
        )

        self.assertEqual(args.profile, "quick")
        self.assertEqual(args.ports, "5430-5435")
        self.assertEqual(args.timeout, 2.0)
        self.assertEqual(args.workers, 10)

    def test_default_profile_configuration_is_not_forced_by_parser(self):
        parser = create_parser()

        args = parser.parse_args(
            ["recon", "localhost"]
        )

        self.assertIsNone(args.profile)
        self.assertIsNone(args.timeout)
        self.assertIsNone(args.workers)
        self.assertIsNone(args.ports)
        self.assertEqual(args.port, 80)


if __name__ == "__main__":
    unittest.main()