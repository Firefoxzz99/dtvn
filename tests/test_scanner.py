import unittest
from unittest.mock import patch
from dtvn.recon.host import TcpProbeResult
from dtvn.recon.scanner import parse_ports, scan_ports


class TestPortScanner(unittest.TestCase):
    def test_parse_ports_valid_formats(self):
        self.assertEqual(parse_ports("5432"), [5432])
        self.assertEqual(parse_ports("5430-5433"), [5430, 5431, 5432, 5433])
        self.assertEqual(parse_ports("443, 80, 5431-5432"), [80, 443, 5431, 5432])

    def test_parse_ports_invalid_inputs(self):
        invalid_specs = ["", "0-5", "65530-65540", "5435-5430", "80,,443", "abc"]
        for spec in invalid_specs:
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_ports(spec)

    @patch("dtvn.recon.scanner.check_tcp_reachability")
    def test_scan_ports_sequential_aggregation(self, mock_probe):
        def fake_probe(target, resolved_ip, port, timeout):
            state = "OPEN" if port == 5432 else "TIMEOUT"
            return TcpProbeResult(
                target=target,
                resolved_ip=resolved_ip,
                port=port,
                state=state,
                detail=f"Mock {state}",
                response_time_ms=1.0 if state == "OPEN" else None,
            )

        mock_probe.side_effect = fake_probe
        summary = scan_ports("localhost", "127.0.0.1", [5431, 5432, 5433], timeout=0.5)

        self.assertEqual(len(summary.results), 3)
        self.assertEqual(len(summary.open_ports), 1)
        self.assertEqual(summary.open_ports[0].port, 5432)
        self.assertEqual(len(summary.timeout_ports), 2)


if __name__ == "__main__":
    unittest.main()