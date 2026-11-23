import json
import tempfile
import unittest
from pathlib import Path
from dtvn.recon.service import ServiceInfo
from dtvn.utils.output import PortFinding, ReconReport
from dtvn.utils.report import save_report_to_json


class TestJsonReport(unittest.TestCase):
    def test_save_report_to_json_creates_valid_file(self):
        report = ReconReport(
            target="localhost",
            target_type="hostname",
            resolved_ip="127.0.0.1",
            mode="multi-port",
            service_probe_enabled=True,
            timeout=0.5,
            findings=[
                PortFinding(
                    port=5432,
                    protocol="tcp",
                    state="OPEN",
                    detail="TCP connection berhasil (port 5432 terbuka)",
                    response_time_ms=1.2,
                    service_info=ServiceInfo(
                        port=5432,
                        protocol="tcp",
                        service="PostgreSQL",
                        identification_method="protocol probe",
                        banner="PostgreSQL SSLRequest -> 'N' (SSL disabled)",
                    ),
                )
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "nested" / "scan.json"
            saved = save_report_to_json(report, str(out_file))
            self.assertTrue(saved.exists())

            data = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(data["metadata"]["tool"], "DTVN")
            self.assertEqual(data["summary"]["open"], 1)
            self.assertEqual(data["findings"][0]["service_info"]["service"], "PostgreSQL")


if __name__ == "__main__":
    unittest.main()