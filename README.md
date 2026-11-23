# DTVN — Network Reconnaissance CLI Toolkit

DTVN adalah alat _Network Reconnaissance_ berbasis Command Line Interface (CLI) yang dibangun menggunakan Python untuk pembelajaran _cybersecurity_ dan pengujian keamanan jaringan yang sah (_authorized testing_).

## Disclaimer Keamanan

Alat ini dibuat murni untuk tujuan edukasi, lab _cybersecurity_, CTF, dan pengujian pada sistem yang memiliki izin eksplisit. Penggunaan terhadap target publik atau sistem pihak lain tanpa izin sangat dilarang.

## Instalasi (Development Mode)

1. Clone repository ini:
   ```bash
   git clone [https://github.com/USERNAME_JENDERAL/dtvn.git](https://github.com/USERNAME_JENDERAL/dtvn.git)
   cd dtvn
   ```

### aktifkan viritual environment

    ```bash
    python -m venv .venv
    source .venv/Scripts/activate  # Untuk Windows (Git Bash)

#install editable
pip install -e .

# penggunaan
# Bantuan & versi
dtvn --help
dtvn --version

# Pemeriksaan satu port TCP spesifik (Phase 2)
dtvn recon localhost --port 5432
dtvn recon 127.0.0.1 --port 80 --timeout 1.5

# Pemindaian rentang atau daftar port TCP secara sekuensial (Phase 3)
dtvn recon localhost --ports 5430-5435 --timeout 0.5
dtvn recon 127.0.0.1 --ports 80,443,5432 --timeout 0.5

