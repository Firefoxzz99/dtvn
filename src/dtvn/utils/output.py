import sys
from dataclasses import dataclass, field
from typing import Optional

from dtvn import __version__
from dtvn.recon.service import ServiceInfo


@dataclass
class PortFinding:
    """Merepresentasikan hasil lengkap satu port (status TCP + identifikasi service)."""

    port: int
    protocol: str
    state: str
    detail: str
    response_time_ms: Optional[float] = None
    service_info: Optional[ServiceInfo] = None


@dataclass
class ReconReport:
    """Wadah laporan terstruktur untuk satu sesi reconnaissance."""

    target: str
    target_type: str
    resolved_ip: str
    mode: str  # "single-port" atau "multi-port"
    service_probe_enabled: bool
    timeout: float
    findings: list[PortFinding] = field(default_factory=list)
    workers: int = 1
    profile: Optional[str] = None

    @property
    def open_count(self) -> int:
        return sum(1 for f in self.findings if f.state == "OPEN")

    @property
    def closed_count(self) -> int:
        return sum(1 for f in self.findings if f.state == "CLOSED")

    @property
    def timeout_count(self) -> int:
        return sum(1 for f in self.findings if f.state == "TIMEOUT")

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.state == "ERROR")


def format_service_label(svc: ServiceInfo) -> str:
    """Memformat teks layanan beserta metode identifikasi dan banner jika ada."""

    base = f"{svc.service} ({svc.identification_method})"

    if svc.banner:
        return f"{base} -> {svc.banner}"

    return base


def print_recon_header(
    target: str,
    target_type: str,
    resolved_ip: str,
    port_count: int,
    service_probe: bool,
    timeout: float,
    workers: int,
    profile: Optional[str],
) -> None:
    """Menampilkan informasi awal sesi reconnaissance sebelum scanning dimulai."""

    probe_mode = "protocol probe" if service_probe else "port-based mapping"
    profile_label = profile if profile is not None else "manual/default"

    print("=" * 68)
    print(f" DTVN v{__version__} — Network Reconnaissance Report")
    print("=" * 68)
    print(f"[*] Target          : {target} ({target_type.upper()})")
    print(f"[*] Resolved IP     : {resolved_ip}")
    print(
        f"[*] Scope           : {port_count} TCP port(s) | "
        f"Mode: {probe_mode} | Timeout: {timeout}s"
    )
    print(f"[*] Profile         : {profile_label}")
    print(f"[*] Workers         : {workers}")
    print("-" * 68)


def render_recon_report(report: ReconReport) -> None:
    """Merender hasil lengkap pemindaian dan ringkasan ke terminal."""

    print(f"  {'PORT':<10} {'STATE':<9} {'LATENCY':<11} SERVICE / INFO")
    print("-" * 68)

    for item in report.findings:
        port_proto = f"{item.port}/{item.protocol}"
        latency = (
            f"{item.response_time_ms} ms"
            if item.response_time_ms is not None
            else "-"
        )

        if item.state == "OPEN" and item.service_info is not None:
            info_text = format_service_label(item.service_info)
        else:
            info_text = item.detail

        print(
            f"  {port_proto:<10} "
            f"{item.state:<9} "
            f"{latency:<11} "
            f"{info_text}"
        )

    print("-" * 68)
    print(
        f"[+] Summary         : "
        f"{report.open_count} OPEN | "
        f"{report.closed_count} CLOSED | "
        f"{report.timeout_count} TIMEOUT | "
        f"{report.error_count} ERROR"
    )
    print("=" * 68)


def print_error(message: str) -> None:
    """Mencetak pesan error secara standar ke stderr."""

    print(f"[!] Error: {message}", file=sys.stderr)