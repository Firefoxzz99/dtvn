import unittest
from unittest.mock import MagicMock, patch
from dtvn.recon.service import identify_service, probe_service


class TestServiceIdentification(unittest.TestCase):
    def test_port_based_mapping(self):
        pg = identify_service(5432)
        self.assertEqual(pg.service, "PostgreSQL")
        self.assertEqual(pg.identification_method, "port-based guess")

        unknown = identify_service(9999)
        self.assertEqual(unknown.service, "Unknown")

    @patch("dtvn.recon.service.socket.socket")
    def test_probe_postgres_ssl_disabled(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"N"
        mock_socket_cls.return_value = mock_sock

        svc = probe_service("localhost", "127.0.0.1", 5432, timeout=1.0)
        self.assertEqual(svc.service, "PostgreSQL")
        self.assertEqual(svc.identification_method, "protocol probe")
        self.assertIn("SSL disabled", svc.banner)

    @patch("dtvn.recon.service.socket.socket")
    def test_probe_ssh_banner(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"
        mock_socket_cls.return_value = mock_sock

        svc = probe_service("localhost", "127.0.0.1", 22, timeout=1.0)
        self.assertEqual(svc.service, "SSH")
        self.assertEqual(svc.identification_method, "protocol probe")
        self.assertEqual(svc.banner, "SSH-2.0-OpenSSH_9.6")

    @patch("dtvn.recon.service.socket.socket")
    def test_probe_http_head(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n"
        mock_socket_cls.return_value = mock_sock

        svc = probe_service("localhost", "127.0.0.1", 80, timeout=1.0)
        self.assertEqual(svc.service, "HTTP")
        self.assertEqual(svc.identification_method, "protocol probe")
        self.assertIn("HTTP/1.1 200 OK", svc.banner)

    def test_probe_fallback_to_port_guess(self):
        svc = probe_service("localhost", "127.0.0.1", 3306, timeout=0.5)
        self.assertEqual(svc.service, "MySQL")
        self.assertEqual(svc.identification_method, "port-based guess")


if __name__ == "__main__":
    unittest.main()