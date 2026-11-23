import ipaddress
import re
from dataclasses import dataclass


@dataclass
class TargetInfo:
    """Menyimpan hasil validasi target secara terstruktur."""
    raw_target: str
    target_type: str  # "ipv4" atau "hostname"


def is_valid_ipv4(value: str) -> bool:
    """Memeriksa apakah string adalah alamat IPv4 yang valid."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    """Memeriksa apakah string memenuhi aturan format hostname (RFC 1123)."""
    if len(value) > 253 or len(value) == 0:
        return False

    # Hapus satu titik di akhir jika ada (FQDN)
    if value.endswith("."):
        value = value[:-1]

    # Pola regex standar untuk setiap label hostname
    label_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    labels = value.split(".")

    # Hostname tidak boleh semuanya angka (itu IP yang salah format)
    if labels[-1].isdigit():
        return False

    return all(label_pattern.match(label) for label in labels)


def validate_target(target: str) -> TargetInfo:
    """
    Memvalidasi target yang diberikan pengguna.
    Mengembalikan TargetInfo jika valid, atau melempar ValueError jika tidak valid.
    """
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target tidak boleh kosong.")

    if is_valid_ipv4(cleaned):
        return TargetInfo(raw_target=cleaned, target_type="ipv4")

    if is_valid_hostname(cleaned):
        return TargetInfo(raw_target=cleaned, target_type="hostname")

    raise ValueError(
        f"Target '{cleaned}' tidak valid. Masukkan alamat IPv4 (contoh: 127.0.0.1) "
        "atau hostname yang sah (contoh: localhost)."
    )