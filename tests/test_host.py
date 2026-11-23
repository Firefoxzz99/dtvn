import socket
import unittest
from unittest.mock import MagicMock, patch
from dtvn.recon.host import check_tcp_reachability, resolve_target


class TestHostRecon(unittest.TestCase):
    @patch("dtvn.recon.host.socket.gethostbyname", return_value="127.0.0.1")
    def test_resolve_target_success(self, mock_dns):
        ip = resolve_target("localhost")
        self.assertEqual(ip, "127.0.0.1")
        mock_dns.assert_called_once_with("localhost")

    @patch("dtvn.recon.host.socket.gethostbyname", side_effect=socket.gaierror("DNS failed"))
    def test_resolve_target_failure(self, _mock_dns):
        with self.assertRaises(ConnectionError):
            resolve_target("nonexistent.invalid")

    @patch("dtvn.recon.host.socket.socket")
    def test_check_tcp_reachability_open(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        res = check_tcp_reachability("localhost", "127.0.0.1", port=5432, timeout=1.0)
        self.assertEqual(res.state, "OPEN")
        self.assertEqual(res.port, 5432)
        self.assertIsNotNone(res.response_time_ms)
        mock_sock.close.assert_called_once()

    @patch("dtvn.recon.host.socket.socket")
    def test_check_tcp_reachability_closed(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket_cls.return_value = mock_sock

        res = check_tcp_reachability("localhost", "127.0.0.1", port=9999, timeout=1.0)
        self.assertEqual(res.state, "CLOSED")
        mock_sock.close.assert_called_once()

    @patch("dtvn.recon.host.socket.socket")
    def test_check_tcp_reachability_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout()
        mock_socket_cls.return_value = mock_sock

        res = check_tcp_reachability("localhost", "127.0.0.1", port=80, timeout=0.5)
        self.assertEqual(res.state, "TIMEOUT")
        self.assertIsNone(res.response_time_ms)
        mock_sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()