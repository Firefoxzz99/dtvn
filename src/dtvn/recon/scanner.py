from dataclasses import dataclass, field
from dtvn.recon.host import TcpProbeResult, check_tcp_reachability


@dataclass
class ScanSummary:
    """Menyimpan kumpulan hasil pemindaian beberapa port TCP pada satu target."""
    target: str
    resolved_ip: str
    results: list[TcpProbeResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[TcpProbeResult]:
        return [r for r in self.results if r.state == "OPEN"]

    @property
    def closed_ports(self) -> list[TcpProbeResult]:
        return [r for r in self.results if r.state == "CLOSED"]

    @property
    def timeout_ports(self) -> list[TcpProbeResult]:
        return [r for r in self.results if r.state == "TIMEOUT"]

    @property
    def error_ports(self) -> list[TcpProbeResult]:
        return [r for r in self.results if r.state == "ERROR"]


def _validate_port_number(port: int) -> None:
    """Memastikan nomor port berada dalam rentang TCP yang sah (1-65535)."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Nomor port {port} tidak valid. Port harus berada di antara 1 hingga 65535.")


def parse_ports(port_spec: str) -> list[int]:
    """
    Mengurai spesifikasi port dari string menjadi daftar nomor port terurut.
    Mendukung:
    - Port tunggal : "5432"
    - Daftar port  : "80,443,5432"
    - Rentang port : "5430-5435"
    - Kombinasi    : "80,5430-5435"
    """
    cleaned = port_spec.strip()
    if not cleaned:
        raise ValueError("Spesifikasi --ports tidak boleh kosong.")

    parsed_ports: set[int] = set()
    parts = cleaned.split(",")

    for raw_part in parts:
        part = raw_part.strip()
        if not part:
            raise ValueError(f"Format daftar port tidak valid pada '{port_spec}'.")

        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not bounds[0].strip() or not bounds[1].strip():
                raise ValueError(
                    f"Format rentang port '{part}' tidak valid. Gunakan format awal-akhir (contoh: 5430-5435)."
                )
            try:
                start_port = int(bounds[0].strip())
                end_port = int(bounds[1].strip())
            except ValueError as err:
                raise ValueError(f"Rentang port '{part}' harus berisi angka bulat.") from err

            _validate_port_number(start_port)
            _validate_port_number(end_port)

            if start_port > end_port:
                raise ValueError(
                    f"Rentang port '{part}' terbalik ({start_port} lebih besar dari {end_port})."
                )

            for port in range(start_port, end_port + 1):
                parsed_ports.add(port)
        else:
            try:
                single_port = int(part)
            except ValueError as err:
                raise ValueError(f"Nilai port '{part}' bukan angka bulat yang valid.") from err

            _validate_port_number(single_port)
            parsed_ports.add(single_port)

    return sorted(parsed_ports)


def scan_ports(
    target: str,
    resolved_ip: str,
    ports: list[int],
    timeout: float = 2.0,
) -> ScanSummary:
    """
    Memindai daftar port TCP secara sekuensial menggunakan check_tcp_reachability()
    dari host.py dan mengumpulkan hasilnya dalam ScanSummary.
    """
    summary = ScanSummary(target=target, resolved_ip=resolved_ip)

    for port in ports:
        probe_result = check_tcp_reachability(
            target=target,
            resolved_ip=resolved_ip,
            port=port,
            timeout=timeout,
        )
        summary.results.append(probe_result)

    return summary