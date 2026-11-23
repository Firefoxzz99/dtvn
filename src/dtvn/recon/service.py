import socket
from dataclasses import dataclass
from typing import Optional

COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
}


@dataclass
class ServiceInfo:
    """Menyimpan hasil identifikasi layanan pada sebuah port TCP."""
    port: int
    protocol: str
    service: str
    identification_method: str
    banner: Optional[str] = None


def identify_service(port: int) -> ServiceInfo:
    """
    Mengidentifikasi kemungkinan layanan berdasarkan nomor port standar (Phase 4A).
    Ini hanya merupakan indikasi (port-based guess), bukan bukti pasti.
    """
    service_name = COMMON_SERVICES.get(port, "Unknown")
    return ServiceInfo(
        port=port,
        protocol="tcp",
        service=service_name,
        identification_method="port-based guess",
    )


def _probe_ssh(resolved_ip: str, port: int, timeout: float) -> Optional[ServiceInfo]:
    """
    Probe khusus protokol SSH (server-first).
    Server SSH langsung mengirim string identifikasi (misal 'SSH-2.0-OpenSSH_...')
    segera setelah koneksi TCP terbentuk.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((resolved_ip, port))
        raw_data = sock.recv(256)
        banner_line = raw_data.decode("utf-8", errors="replace").strip().splitlines()[0]
        if banner_line.startswith("SSH-"):
            return ServiceInfo(
                port=port,
                protocol="tcp",
                service="SSH",
                identification_method="protocol probe",
                banner=banner_line,
            )
    except (OSError, IndexError):
        pass
    finally:
        sock.close()
    return None


def _probe_http(
    target: str, resolved_ip: str, port: int, timeout: float
) -> Optional[ServiceInfo]:
    """
    Probe khusus protokol HTTP (client-first).
    Mengirim permintaan HEAD minimal yang aman dan membaca baris status serta header Server.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((resolved_ip, port))
        request = f"HEAD / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: DTVN-Recon/0.1\r\n\r\n"
        sock.sendall(request.encode("ascii", errors="ignore"))

        raw_data = sock.recv(512)
        text = raw_data.decode("utf-8", errors="replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]

        if lines and lines[0].startswith("HTTP/"):
            server_header = next(
                (line for line in lines[1:] if line.lower().startswith("server:")),
                None,
            )
            detail = f"{lines[0]} ({server_header})" if server_header else lines[0]
            return ServiceInfo(
                port=port,
                protocol="tcp",
                service="HTTP",
                identification_method="protocol probe",
                banner=detail,
            )
    except OSError:
        pass
    finally:
        sock.close()
    return None


def _probe_postgres(resolved_ip: str, port: int, timeout: float) -> Optional[ServiceInfo]:
    """
    Probe khusus protokol PostgreSQL (biner).
    Mengirim paket resmi PostgreSQL SSLRequest (8 byte) tanpa autentikasi.
    Server PostgreSQL merespons tepat 1 byte: 'S' (SSL didukung) atau 'N' (SSL nonaktif).
    """
    # Panjang paket = 8 byte (\x00\x00\x00\x08), kode SSLRequest = 80877103 (\x04\xd2\x16\x2f)
    ssl_request_packet = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((resolved_ip, port))
        sock.sendall(ssl_request_packet)

        response = sock.recv(1)
        if response in (b"S", b"N"):
            ssl_status = "SSL supported" if response == b"S" else "SSL disabled"
            return ServiceInfo(
                port=port,
                protocol="tcp",
                service="PostgreSQL",
                identification_method="protocol probe",
                banner=f"PostgreSQL SSLRequest -> '{response.decode('ascii')}' ({ssl_status})",
            )
    except OSError:
        pass
    finally:
        sock.close()
    return None


def probe_service(
    target: str, resolved_ip: str, port: int, timeout: float = 2.0
) -> ServiceInfo:
    """
    Menjalankan protocol-specific probing yang aman untuk port OPEN.
    Jika protokol tidak didukung atau probe tidak mendapat respons valid,
    otomatis kembali (fallback) ke port-based guess dari Phase 4A.
    """
    probed: Optional[ServiceInfo] = None

    if port == 22:
        probed = _probe_ssh(resolved_ip, port, timeout)
    elif port in (80, 8080):
        probed = _probe_http(target, resolved_ip, port, timeout)
    elif port == 5432:
        probed = _probe_postgres(resolved_ip, port, timeout)

    if probed is not None:
        return probed

    # Fallback aman ke port-based guess jika tidak terkonfirmasi oleh probe
    return identify_service(port)