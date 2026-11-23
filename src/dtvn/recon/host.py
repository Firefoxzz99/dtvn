import socket
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TcpProbeResult:
    """Menyimpan hasil pemeriksaan koneksi TCP ke satu port spesifik."""
    target: str
    resolved_ip: str
    port: int
    state: str  # "OPEN", "CLOSED", "TIMEOUT", atau "ERROR"
    detail: str
    response_time_ms: Optional[float] = None


def resolve_target(target: str) -> str:
    """
    Menerjemahkan hostname menjadi alamat IPv4.
    Jika target sudah IPv4, mengembalikan IP tersebut.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as err:
        raise ConnectionError(
            f"Gagal menerjemahkan hostname '{target}' ke alamat IP (DNS Lookup gagal)."
        ) from err


def check_tcp_reachability(
    target: str,
    resolved_ip: str,
    port: int = 80,
    timeout: float = 2.0,
) -> TcpProbeResult:
    """
    Mengecek keterjangkauan satu port TCP spesifik pada target.
    Membedakan kondisi: OPEN (berhasil), CLOSED (refused), dan TIMEOUT (filtered/no response).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    start_time = time.perf_counter()
    try:
        # 1. TCP Connection berhasil -> Port terbuka dan layanan aktif
        sock.connect((resolved_ip, port))
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return TcpProbeResult(
            target=target,
            resolved_ip=resolved_ip,
            port=port,
            state="OPEN",
            detail=f"TCP connection berhasil (port {port} terbuka)",
            response_time_ms=elapsed_ms,
        )

    except ConnectionRefusedError:
        # 2. Connection refused -> Host aktif merespons, tetapi port tertutup
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return TcpProbeResult(
            target=target,
            resolved_ip=resolved_ip,
            port=port,
            state="CLOSED",
            detail=f"Connection refused (host aktif, port {port} tertutup)",
            response_time_ms=elapsed_ms,
        )

    except socket.timeout:
        # 3. Timeout -> Tidak ada balasan dalam batas waktu (kemungkinan filtered atau host tidak merespons)
        return TcpProbeResult(
            target=target,
            resolved_ip=resolved_ip,
            port=port,
            state="TIMEOUT",
            detail=f"Timeout setelah {timeout} detik (port {port} filtered atau tidak merespons)",
        )

    except OSError as err:
        return TcpProbeResult(
            target=target,
            resolved_ip=resolved_ip,
            port=port,
            state="ERROR",
            detail=f"Error jaringan pada port {port}: {err}",
        )

    finally:
        sock.close()