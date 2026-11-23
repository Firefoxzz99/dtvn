from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Menyimpan konfigurasi scanning yang digunakan oleh sebuah profile DTVN."""

    name: str
    ports: str
    timeout: float
    workers: int


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        ports="21,22,80,443,5432,3306",
        timeout=0.5,
        workers=5,
    ),
    "standard": ScanProfile(
        name="standard",
        ports="21,22,25,53,80,443,3306,5432",
        timeout=1.0,
        workers=10,
    ),
    "thorough": ScanProfile(
        name="thorough",
        ports="1-1024",
        timeout=1.0,
        workers=20,
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Mengambil profile berdasarkan nama."""

    normalized_name = name.strip().lower()

    try:
        return PROFILES[normalized_name]
    except KeyError as err:
        available = ", ".join(sorted(PROFILES))
        raise ValueError(
            f"Profile '{name}' tidak dikenal. "
            f"Profile yang tersedia: {available}."
        ) from err