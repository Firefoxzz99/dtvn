import argparse
import sys
from dtvn import __version__
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

    # Wadah untuk subcommands (seperti 'recon')
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        help="Subcommand yang tersedia",
    )

    # Subcommand: dtvn recon <target>
    recon_parser = subparsers.add_parser(
        "recon",
        help="Jalankan pengintaian jaringan dasar pada target yang diizinkan.",
    )
    recon_parser.add_argument(
        "target",
        type=str,
        help="Alamat IPv4 (contoh: 127.0.0.1) atau hostname target (contoh: localhost).",
    )

    return parser


def main() -> None:
    """Titik masuk (entry point) utama untuk perintah CLI DTVN."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "recon":
        try:
            target_info = validate_target(args.target)
            print(f"[+] Target valid terdeteksi : {target_info.raw_target}")
            print(f"[+] Tipe target             : {target_info.target_type.upper()}")
        except ValueError as err:
            print(f"[!] Error: {err}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()