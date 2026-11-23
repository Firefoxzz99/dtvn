# DTVN — Network Reconnaissance CLI Toolkit

DTVN adalah alat *Network Reconnaissance* berbasis Command Line Interface (CLI) yang dibangun menggunakan Python untuk pembelajaran *cybersecurity* dan pengujian keamanan jaringan yang sah (*authorized testing*).

## Disclaimer Keamanan
Alat ini dibuat murni untuk tujuan edukasi, lab *cybersecurity*, CTF, dan pengujian pada sistem yang memiliki izin eksplisit. Penggunaan terhadap target publik atau sistem pihak lain tanpa izin sangat dilarang.

## Instalasi (Development Mode)

1. Clone repository ini:
   ```bash
   git clone [https://github.com/Firefoxzz99/dtvn.git](https://github.com/Firefoxzz99/dtvn.git)
   cd dtvn

### blue print sementara
src/dtvn/
├── __init__.py
├── cli.py              <-- (Diubah) Menambahkan subcommand 'recon' & argumen 'target'
└── recon/              <-- (Folder Baru) Paket khusus modul reconnaissance
    ├── __init__.py     <-- (Baru) Penanda package recon
    └── target.py       <-- (Baru) Logika validasi IP Address & Hostname

### blueprint baru untuk phase 2
src/dtvn/
├── __init__.py
├── cli.py              <-- (Diubah) Menambahkan opsi --timeout dan memanggil recon host
└── recon/
    ├── __init__.py
    ├── target.py       <-- (Tetap) Validasi IPv4 & Hostname
    └── host.py         <-- (Baru) DNS Resolution & TCP Port Reachability Check