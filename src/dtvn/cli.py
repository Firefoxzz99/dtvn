import argparse
import sys
from dtvn import __version__
from dtvn.recon.host import check_tcp_reachability, resolve_target
from dtvn.recon.scanner import parse_ports, scan_ports
from dtvn.recon.service import ServiceInfo, identify_service, probe_service
from dtvn.recon.target import validate_target


def create_parser() -> argparse.ArgumentParser:
    """Membangun parser argumen CLI untuk DTVN."""
    parser = argparse.ArgumentParser(
        prog="dtvn",
        description="DTVN - Network Reconnaissance CLI Toolkit for authorized security testing.",
    )
    parser.add_argument(
        "-v", "--version",
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

    # Subcommand: dtvn recon <target> [--port 80 | --ports 5430-5435] [--service-probe] [--timeout 2.0]
    recon_parser = subparsers.add_parser(
        "recon",
        help="Jalankan pengintaian jaringan dasar pada target yang diizinkan.",
    )
    recon_parser.add_argument(
        "target",
        type=str,
        help="Alamat IPv4 (contoh: 127.0.0.1) atau hostname target (contoh: localhost).",
    )

    # Grup mutually exclusive: pengguna memilih single --port ATAU multi --ports
    port_group = recon_parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--port",
        type=int,
        default=80,
        help="Port TCP tunggal untuk pemeriksaan konektivitas (default: 80).",
    )
    port_group.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Daftar atau rentang port TCP untuk dipindai (contoh: 5430-5435 atau 80,443,5432).",
    )

    recon_parser.add_argument(
        "--service-probe",
        action="store_true",
        help="Jalankan protocol-specific service probing yang aman pada port berstatus OPEN.",
    )

    recon_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Batas waktu tunggu koneksi per port dalam detik (default: 2.0).",
    )

    return parser


def _format_service_output(svc: ServiceInfo) -> str:
    """Memformat teks identifikasi service secara konsisten."""
    base = f"{svc.service} ({svc.identification_method})"
    if svc.banner:
        return f"{base} -> {svc.banner}"
    return base


def main() -> None:
    """Titik masuk (entry point) utama untuk perintah CLI DTVN."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "recon":
        if args.timeout <= 0:
            print("[!] Error: Nilai --timeout harus lebih besar dari 0.", file=sys.stderr)
            sys.exit(1)

        try:
            # 1. Validasi format target (Phase 1)
            target_info = validate_target(args.target)

            # 2. Validasi input port sebelum melakukan koneksi jaringan
            if args.ports is not None:
                port_list = parse_ports(args.ports)
            else:
                if not (1 <= args.port <= 65535):
                    raise ValueError("Nomor --port harus berada di antara 1 hingga 65535.")
                port_list = None

            print(f"[*] Target          : {target_info.raw_target} ({target_info.target_type.upper()})")

            # 3. Resolusi DNS ke IPv4 (Phase 2)
            resolved_ip = resolve_target(target_info.raw_target)
            print(f"[*] Resolved IP     : {resolved_ip}")

            # 4A. Mode Multi-Port Scanner (Phase 3 & Phase 4)
            if port_list is not None:
                mode_label = "dengan protocol service probe" if args.service_probe else "port-based mapping"
                print(
                    f"[*] Scanning        : {len(port_list)} port(s) secara sekuensial "
                    f"({mode_label}, timeout: {args.timeout}s)..."
                )
                summary = scan_ports(
                    target=target_info.raw_target,
                    resolved_ip=resolved_ip,
                    ports=port_list,
                    timeout=args.timeout,
                )
                print("-" * 64)
                for res in summary.results:
                    if res.state == "OPEN":
                        svc = (
                            probe_service(target_info.raw_target, resolved_ip, res.port, args.timeout)
                            if args.service_probe
                            else identify_service(res.port)
                        )
                        svc_text = _format_service_output(svc)
                        latency = f" [{res.response_time_ms} ms]" if res.response_time_ms is not None else ""
                        print(f"  {res.port}/tcp  OPEN    {svc_text}{latency}")
                    else:
                        print(f"  {res.port}/tcp  {res.state}")
                print("-" * 64)
                print(
                    f"[+] Ringkasan       : "
                    f"{len(summary.open_ports)} OPEN | "
                    f"{len(summary.closed_ports)} CLOSED | "
                    f"{len(summary.timeout_ports)} TIMEOUT | "
                    f"{len(summary.error_ports)} ERROR"
                )

            # 4B. Mode Single-Port Probe (Phase 2 + Phase 4)
            else:
                print(f"[*] TCP Probe       : {resolved_ip}:{args.port} (timeout: {args.timeout}s)...")
                probe_result = check_tcp_reachability(
                    target=target_info.raw_target,
                    resolved_ip=resolved_ip,
                    port=args.port,
                    timeout=args.timeout,
                )

                print(f"[+] Port Status     : {probe_result.state}")
                print(f"[+] Detail          : {probe_result.detail}")
                if probe_result.state == "OPEN":
                    svc = (
                        probe_service(target_info.raw_target, resolved_ip, args.port, args.timeout)
                        if args.service_probe
                        else identify_service(args.port)
                    )
                    print(f"[+] Service         : {_format_service_output(svc)}")
                if probe_result.response_time_ms is not None:
                    print(f"[+] Response Time   : {probe_result.response_time_ms} ms")

        except (ValueError, ConnectionError) as err:
            print(f"[!] Error: {err}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()