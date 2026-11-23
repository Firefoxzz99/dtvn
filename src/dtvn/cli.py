import argparse
import sys

from dtvn import __version__
from dtvn.recon.host import check_tcp_reachability, resolve_target
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

    # Wadah untuk subcommands
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        help="Subcommand yang tersedia",
    )

    # Subcommand:
    # dtvn recon <target>
    # [--port 80 | --ports 5430-5435]
    # [--service-probe]
    # [--timeout 2.0]
    # [--workers 10]
    # [-o results/scan.json]
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
        default=2.0,
        help=(
            "Batas waktu tunggu koneksi per port dalam detik "
            "(default: 2.0)."
        ),
    )

    recon_parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help=(
            "Jumlah worker concurrent untuk multi-port scanning. "
            "Nilai 1 menggunakan scanner sequential (default: 1)."
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
        if args.timeout <= 0:
            print_error("Nilai --timeout harus lebih besar dari 0.")
            sys.exit(1)

        if args.workers < 1:
            print_error("Nilai --workers harus minimal 1.")
            sys.exit(1)

        if args.workers > 100:
            print_error("Nilai --workers tidak boleh lebih dari 100.")
            sys.exit(1)

        try:
            # 1. Validasi format target (Phase 1)
            target_info = validate_target(args.target)

            # 2. Validasi input port sebelum melakukan koneksi jaringan
            if args.ports is not None:
                port_list = parse_ports(args.ports)
                mode = "multi-port"
            else:
                if not (1 <= args.port <= 65535):
                    raise ValueError(
                        "Nomor --port harus berada di antara 1 hingga 65535."
                    )

                port_list = [args.port]
                mode = "single-port"

            # 3. Resolusi DNS ke IPv4 (Phase 2)
            resolved_ip = resolve_target(target_info.raw_target)

            # 4. Tampilkan header sesi recon (Phase 5)
            print_recon_header(
                target=target_info.raw_target,
                target_type=target_info.target_type,
                resolved_ip=resolved_ip,
                port_count=len(port_list),
                service_probe=args.service_probe,
                timeout=args.timeout,
            )

            # 5. Jalankan scanning
            if mode == "multi-port":
                if args.workers == 1:
                    scan_summary = scan_ports(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        ports=port_list,
                        timeout=args.timeout,
                    )
                else:
                    scan_summary = scan_ports_concurrent(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        ports=port_list,
                        timeout=args.timeout,
                        max_workers=args.workers,
                    )

                probe_results = scan_summary.results

            else:
                single_result = check_tcp_reachability(
                    target=target_info.raw_target,
                    resolved_ip=resolved_ip,
                    port=args.port,
                    timeout=args.timeout,
                )

                probe_results = [single_result]

            findings: list[PortFinding] = []

            for res in probe_results:
                svc_info = (
                    _resolve_service(
                        target=target_info.raw_target,
                        resolved_ip=resolved_ip,
                        port=res.port,
                        timeout=args.timeout,
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

            # 6. Susun laporan terstruktur dan render ke terminal
            report = ReconReport(
                target=target_info.raw_target,
                target_type=target_info.target_type,
                resolved_ip=resolved_ip,
                mode=mode,
                service_probe_enabled=args.service_probe,
                timeout=args.timeout,
                findings=findings,
            )

            render_recon_report(report)

            # 7. Ekspor laporan ke JSON
            if args.output is not None:
                saved_path = save_report_to_json(report, args.output)
                print(f"[+] JSON Report     : Tersimpan di '{saved_path}'")

        except (ValueError, ConnectionError, OSError) as err:
            print_error(str(err))
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()