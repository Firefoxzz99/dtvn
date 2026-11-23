import argparse
import sys

from dtvn import __version__
from dtvn.recon.host import check_tcp_reachability, resolve_target
from dtvn.recon.profile import get_profile
from dtvn.recon.scanner import (
    parse_ports,
    scan_ports,
    scan_ports_concurrent,
)
from dtvn.recon.service import identify_service, probe_service
from dtvn.recon.target import validate_target
from dtvn.utils.output import (
    PortFinding,
    ReconReport,
    print_error,
    print_recon_header,
    render_recon_report,
)
from dtvn.utils.report import save_report_to_json


def create_parser() -> argparse.ArgumentParser:
    """Membangun parser argumen CLI untuk DTVN."""
    parser = argparse.ArgumentParser(
        prog="dtvn",
        description=(
            "DTVN - Network Reconnaissance CLI Toolkit "
            "for authorized security testing."
        ),
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Tampilkan versi program DTVN dan keluar.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        help="Subcommand yang tersedia",
    )

    recon_parser = subparsers.add_parser(
        "recon",
        help="Jalankan pengintaian jaringan dasar pada target yang diizinkan.",
    )

    recon_parser.add_argument(
        "target",
        type=str,
        help=(
            "Alamat IPv4 (contoh: 127.0.0.1) "
            "atau hostname target (contoh: localhost)."
        ),
    )

    recon_parser.add_argument(
        "--profile",
        type=str,
        default=None,
        choices=["quick", "standard", "thorough"],
        help=(
            "Gunakan preset konfigurasi scanning "
            "(quick, standard, atau thorough)."
        ),
    )

    port_group = recon_parser.add_mutually_exclusive_group()

    port_group.add_argument(
        "-p",
        "--port",
        type=int,
        default=80,
        help=(
            "Port TCP tunggal untuk pemeriksaan konektivitas "
            "(default: 80)."
        ),
    )

    port_group.add_argument(
        "--ports",
        type=str,
        default=None,
        help=(
            "Daftar atau rentang port TCP untuk dipindai "
            "(contoh: 5430-5435 atau 80,443,5432)."
        ),
    )

    recon_parser.add_argument(
        "--service-probe",
        action="store_true",
        help=(
            "Jalankan protocol-specific service probing yang aman "
            "pada port berstatus OPEN."
        ),
    )

    recon_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help=(
            "Batas waktu tunggu koneksi per port dalam detik. "
            "Jika tidak diberikan, gunakan nilai dari profile "
            "atau default 2.0."
        ),
    )

    recon_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Jumlah worker concurrent untuk multi-port scanning. "
            "Jika tidak diberikan, gunakan nilai dari profile "
            "atau default 1."
        ),
    )

    recon_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help=(
            "Simpan laporan hasil reconnaissance ke file JSON "
            "(contoh: results/scan.json)."
        ),
    )

    return parser


def _resolve_service(
    target: str,
    resolved_ip: str,
    port: int,
    timeout: float,
    use_probe: bool,
):
    """Memilih metode identifikasi layanan."""
    if use_probe:
        return probe_service(target, resolved_ip, port, timeout)

    return identify_service(port)


def main() -> None:
    """Titik masuk utama untuk perintah CLI DTVN."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "recon":
        try:
            # ---------------------------------------------------------
            # 1. Ambil konfigurasi profile jika digunakan
            # ---------------------------------------------------------
            profile = get_profile(args.profile) if args.profile else None

            # ---------------------------------------------------------
            # 2. Tentukan konfigurasi efektif.
            #
            # Flag manual selalu memiliki prioritas lebih tinggi
            # daripada nilai profile.
            # ---------------------------------------------------------
            effective_timeout = (
                args.timeout
                if args.timeout is not None
                else profile.timeout
                if profile is not None
                else 2.0
            )

            effective_workers = (
                args.workers
                if args.workers is not None
                else profile.workers
                if profile is not None
                else 1
            )

            # ---------------------------------------------------------
            # 3. Validasi timeout dan workers
            # ---------------------------------------------------------
            if effective_timeout <= 0:
                raise ValueError("Nilai --timeout harus lebih besar dari 0.")

            if not (1 <= effective_workers <= 100):
                raise ValueError(
                    "Nilai --workers harus berada di antara 1 hingga 100."
                )

            # ---------------------------------------------------------
            # 4. Validasi target
            # ---------------------------------------------------------
            target_info = validate_target(args.target)

            # ---------------------------------------------------------
            # 5. Tentukan port scanning.
            #
            # Prioritas:
            # --ports / -p manual
            #        ↓
            # profile
            #        ↓
            # default
            # ---------------------------------------------------------
            if args.ports is not None:
                port_list = parse_ports(args.ports)
                mode = "multi-port"

            elif profile is not None:
                port_list = parse_ports(profile.ports)
                mode = "multi-port"

            else:
                if not (1 <= args.port <= 65535):
                    raise ValueError(
                        "Nomor --port harus berada di antara 1 hingga 65535."
                    )

                port_list = [args.port]
                mode = "single-port"

            # ---------------------------------------------------------
            # 6. Resolusi DNS
            # ---------------------------------------------------------
            resolved_ip = resolve_target(target_info.raw_target)

            # ---------------------------------------------------------
            # 7. Header report
            # ---------------------------------------------------------
            print_recon_header(
                target=target_info.raw_target,
                target_type=target_info.target_type,
                resolved_ip=resolved_ip,
                port_count=len(port_list),
                service_probe=args.service_probe,
                timeout=effective_timeout,
            )

            # ---------------------------------------------------------
            # 8. Jalankan scanning
            # ---------------------------------------------------------
            if mode == "multi-port":
                if effective_workers == 1:
                    scan_summary = scan_ports(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        ports=port_list,
                        timeout=effective_timeout,
                    )
                else:
                    scan_summary = scan_ports_concurrent(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        ports=port_list,
                        timeout=effective_timeout,
                        max_workers=effective_workers,
                    )

                probe_results = scan_summary.results

            else:
                single_result = check_tcp_reachability(
                    target=target_info.raw_target,
                    resolved_ip=resolved_ip,
                    port=args.port,
                    timeout=effective_timeout,
                )

                probe_results = [single_result]

            # ---------------------------------------------------------
            # 9. Bangun findings
            # ---------------------------------------------------------
            findings: list[PortFinding] = []

            for res in probe_results:
                svc_info = (
                    _resolve_service(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        port=res.port,
                        timeout=effective_timeout,
                        use_probe=args.service_probe,
                    )
                    if res.state == "OPEN"
                    else None
                )

                findings.append(
                    PortFinding(
                        port=res.port,
                        protocol="tcp",
                        state=res.state,
                        detail=res.detail,
                        response_time_ms=res.response_time_ms,
                        service_info=svc_info,
                    )
                )

            # ---------------------------------------------------------
            # 10. Susun report
            # ---------------------------------------------------------
            report = ReconReport(
                target=target_info.raw_target,
                target_type=target_info.target_type,
                resolved_ip=resolved_ip,
                mode=mode,
                service_probe_enabled=args.service_probe,
                timeout=effective_timeout,
                findings=findings,
            )

            render_recon_report(report)

            # ---------------------------------------------------------
            # 11. JSON export
            # ---------------------------------------------------------
            if args.output is not None:
                saved_path = save_report_to_json(
                    report,
                    args.output,
                )

                print(
                    f"[+] JSON Report     : Tersimpan di '{saved_path}'"
                )

        except (ValueError, ConnectionError, OSError) as err:
            print_error(str(err))
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()