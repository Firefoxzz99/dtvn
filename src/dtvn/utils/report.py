import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dtvn import __version__
from dtvn.utils.output import ReconReport


def serialize_recon_report(report: ReconReport) -> dict[str, Any]:
    """
    Mengonversi objek ReconReport menjadi dictionary terstruktur
    yang siap diserialisasi ke format JSON.
    """
    raw_data = asdict(report)

    return {
        "metadata": {
            "tool": "DTVN",
            "version": __version__,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "scan_config": {
            "target": raw_data["target"],
            "target_type": raw_data["target_type"],
            "resolved_ip": raw_data["resolved_ip"],
            "mode": raw_data["mode"],
            "service_probe_enabled": raw_data["service_probe_enabled"],
            "timeout_seconds": raw_data["timeout"],
        },
        "summary": {
            "total_ports": len(report.findings),
            "open": report.open_count,
            "closed": report.closed_count,
            "timeout": report.timeout_count,
            "error": report.error_count,
        },
        "findings": raw_data["findings"],
    }


def save_report_to_json(report: ReconReport, output_path: str) -> Path:
    """
    Menyimpan ReconReport ke file JSON pada path yang ditentukan.
    Membuat direktori induk secara otomatis jika belum tersedia.
    """
    cleaned_path = output_path.strip()
    if not cleaned_path:
        raise ValueError("Path file --output tidak boleh kosong.")

    target_file = Path(cleaned_path)
    if target_file.exists() and target_file.is_dir():
        raise ValueError(f"Path '{cleaned_path}' adalah direktori, bukan nama file JSON.")

    # Buat direktori induk jika belum ada (misal folder 'results/')
    target_file.parent.mkdir(parents=True, exist_ok=True)

    payload = serialize_recon_report(report)
    with target_file.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return target_file