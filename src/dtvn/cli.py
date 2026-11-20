import argparse
import sys
from dtvn import __version__


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
    return parser


def main() -> None:
    """Titik masuk (entry point) utama untuk perintah CLI DTVN."""
    parser = create_parser()
    args = parser.parse_args()

    # Jika pengguna hanya mengetik 'dtvn' tanpa argumen tambahan
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == "__main__":
    main()