import argparse
import sys
from dtvn import __version__
from dtvn.recon.host import check_tcp_reachability, resolve_target
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

    # Subcommand: dtvn recon <target> [--port 80] [--timeout 2.0]
    recon_parser = subparsers.add_parser(
        "recon",
        help="Jalankan pengintaian jaringan dasar pada target yang diizinkan.",
    )
    recon_parser.add_argument(
        "target",
        type=str,
        help="Alamat IPv4 (contoh: 127.0.0.1) atau hostname target (contoh: localhost).",
    )
    recon_parser.add_argument(
        "-p", "--port",
        type=int,
        default=80,
        help="Port TCP target untuk pemeriksaan konektivitas (default: 80).",
    )
    recon_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Batas waktu tunggu koneksi dalam detik (default: 2.0).",
    )

    return parser


def main() -> None:
    """Titik masuk (entry point) utama untuk perintah CLI DTVN."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "recon":
        if args.timeout <= 0:
            print("[!] Error: Nilai --timeout harus lebih besar dari 0.", file=sys.stderr)
            sys.exit(1)

        if not (1 <= args.port <= 65535):
            print("[!] Error: Nomor --port harus berada di antara 1 hingga 65535.", file=sys.stderr)
            sys.exit(1)

        try:
            # 1. Validasi format target (Phase 1)
            target_info = validate_target(args.target)
            print(f"[*] Target          : {target_info.raw_target} ({target_info.target_type.upper()})")

            # 2. Resolusi DNS ke IPv4 (Phase 2)
            resolved_ip = resolve_target(target_info.raw_target)
            print(f"[*] Resolved IP     : {resolved_ip}")

            # 3. Cek keterjangkauan port TCP (Phase 2)
            print(f"[*] TCP Probe       : {resolved_ip}:{args.port} (timeout: {args.timeout}s)...")
            probe_result = check_tcp_reachability(
                target=target_info.raw_target,
                resolved_ip=resolved_ip,
                port=args.port,
                timeout=args.timeout,
            )

            print(f"[+] Port Status     : {probe_result.state}")
            print(f"[+] Detail          : {probe_result.detail}")
            if probe_result.response_time_ms is not None:
                print(f"[+] Response Time   : {probe_result.response_time_ms} ms")

        except (ValueError, ConnectionError) as err:
            print(f"[!] Error: {err}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
    