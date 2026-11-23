

===============================




# DTVN — Modular Network Reconnaissance CLI Toolkit

**DTVN** is a modular, educational, and security-focused Python Command-Line Interface (CLI) toolkit built to perform structured network reconnaissance in authorized environments.

Designed incrementally from the ground up using Python's standard library (`socket`, `ipaddress`, `argparse`, `dataclasses`, `json`, `unittest`), DTVN emphasizes **clean software architecture**, **defensive input validation**, **accurate TCP state classification**, and **non-intrusive protocol-specific service probing**.

---

## Disclaimer & Authorized Use Policy

> **IMPORTANT:** DTVN is developed strictly for educational purposes, cybersecurity labs, Capture The Flag (CTF) competitions, and authorized security assessments.
>
> **Do NOT use this tool against public infrastructure or networks without explicit written permission.** DTVN intentionally excludes exploitation, brute-force credential testing, stealth/evasion techniques, and aggressive flood scanning.

---

## Key Features

* **Strict Target Validation (`target.py`):** Validates IPv4 addresses (`ipaddress.IPv4Address`) and RFC-compliant hostnames while rejecting malformed or shell-injection-like strings before any network call occurs.
* **DNS Resolution & Single TCP Probe (`host.py`):** Translates hostnames to IPv4 and classifies single TCP port reachability accurately into `OPEN`, `CLOSED` (connection refused), `TIMEOUT` (filtered/unresponsive), or `ERROR` with millisecond latency tracking.
* **Sequential Multi-Port Scanner (`scanner.py`):** Parses single ports (`5432`), comma-separated lists (`80,443,5432`), and port ranges (`5430-5435`) with strict boundary checks (`1–65535`) and reversed-range detection.
* **Two-Tier Service Identification (`service.py`):**
  * **Port-Based Mapping:** Provides transparent port-convention hints labeled explicitly as `(port-based guess)`.
  * **Protocol-Specific Probing (`--service-probe`):** Safely verifies active services using protocol-aware handshakes without authentication:
    * **SSH:** Captures server-first identification banners (`SSH-2.0-...`).
    * **HTTP:** Sends lightweight `HEAD / HTTP/1.0` requests and extracts status lines and `Server` headers.
    * **PostgreSQL:** Sends an official 8-byte binary `SSLRequest` packet and inspects the 1-byte backend response (`'S'` or `'N'`).
* **Structured Terminal & JSON Reporting (`utils/output.py`, `utils/report.py`):** Renders clean tabular console reports and exports machine-readable JSON reports complete with UTC ISO-8601 timestamps and scan metadata (`--output results/scan.json`).
* **Automated Unit Test Suite (`tests/`):** 18 fast, deterministic unit tests utilizing `unittest.mock` to validate all components offline.

---

## Architecture Overview

DTVN enforces strict **Separation of Concerns** across its modules:

```text
User Input (CLI Arguments)
       │
       ▼
[1] target.py   ──► Validates IPv4 / Hostname format (rejects unsafe input)
       │
       ▼
[2] host.py     ──► Resolves DNS & executes single-port TCP socket probes
       │
       ▼
[3] scanner.py  ──► Parses port ranges & orchestrates sequential multi-port scans
       │
       ▼
[4] service.py  ──► Maps standard ports or runs safe protocol-specific probes
       │
       ▼
[5] utils/
    ├── output.py ──► Formats unified ReconReport & renders terminal table
    └── report.py ──► Serializes ReconReport with UTC metadata to JSON

```plaintext
dtvn/
├── src/
│   └── dtvn/
│       ├── __init__.py
│       ├── cli.py              # CLI argument parser & workflow orchestrator
│       ├── recon/
│       │   ├── __init__.py
│       │   ├── target.py       # Input validation (IPv4 & Hostname)
│       │   ├── host.py         # DNS lookup & TCP socket reachability probe
│       │   ├── scanner.py      # Port specification parser & sequential scanner
│       │   └── service.py      # Port-based guess & SSH/HTTP/PostgreSQL probes
│       └── utils/
│           ├── __init__.py
│           ├── output.py       # Terminal presentation layer & report dataclasses
│           └── report.py       # JSON serialization & file export
├── tests/
│   ├── __init__.py
│   ├── test_target.py
│   ├── test_host.py
│   ├── test_scanner.py
│   ├── test_service.py
│   └── test_report.py
├── .gitignore
├── pyproject.toml
└── README.md
```

## Installation
## Prerequisites: Python 3.10+ and Git.

* Clone the repository:

```Bash
git clone [https://github.com/](https://github.com/)Firefoxzz99/dtvn.git
cd dtvn
```

* Create and activate a virtual environment:

```Bash
python -m venv .venv
# Windows (Git Bash):
source .venv/Scripts/activate
# Linux / macOS:
source .venv/bin/activate
```

* Install DTVN in editable mode:

```Bash
pip install -e .
```
===

## Usage Examples
1. Check CLI Help & Version
```Bash
dtvn --help
dtvn --version
dtvn recon --help
```
2. Single TCP Port Probe
```Bash
dtvn recon localhost --port 5432
```
3. Sequential Multi-Port Scan (Port-Based Guess)
```Bash
dtvn recon localhost --ports 5430-5435 --timeout 0.5
```
4. Multi-Port Scan with Safe Protocol Probing & JSON Export
```Bash
dtvn recon localhost --ports 5430-5435 --service-probe --timeout 0.5 --output results/scan.json
```

Semple Terminal Output 
```plaintext
====================================================================
 DTVN v0.1.0 — Network Reconnaissance Report
====================================================================
[*] Target          : localhost (HOSTNAME)
[*] Resolved IP     : 127.0.0.1
[*] Scope           : 6 TCP port(s) | Mode: protocol probe | Timeout: 0.5s
--------------------------------------------------------------------
  PORT       STATE     LATENCY     SERVICE / INFO
--------------------------------------------------------------------
  5430/tcp   TIMEOUT   -           Timeout setelah 0.5 detik (port 5430 filtered atau tidak merespons)
  5431/tcp   TIMEOUT   -           Timeout setelah 0.5 detik (port 5431 filtered atau tidak merespons)
  5432/tcp   OPEN      15.4 ms     PostgreSQL (protocol probe) -> PostgreSQL SSLRequest -> 'N' (SSL disabled)
  5433/tcp   TIMEOUT   -           Timeout setelah 0.5 detik (port 5433 filtered atau tidak merespons)
  5434/tcp   TIMEOUT   -           Timeout setelah 0.5 detik (port 5434 filtered atau tidak merespons)
  5435/tcp   TIMEOUT   -           Timeout setelah 0.5 detik (port 5435 filtered atau tidak merespons)
--------------------------------------------------------------------
[+] Summary         : 1 OPEN | 0 CLOSED | 5 TIMEOUT | 0 ERROR
====================================================================
[+] JSON Report     : Tersimpan di 'results/scan.json'
```
## Running Automated Tests
DTVN uses Python's built-in unittest framework with socket mocking so the entire test suite runs offline in milliseconds:
```bash
python -m unittest discover -s tests -v
```
# Development Roadmap
[x] Phase 0: CLI Foundation & Packaging (src/ layout, pyproject.toml)

[x] Phase 1: Strict Target Validation (IPv4 & Hostname)

[x] Phase 2: DNS Resolution & Single-Port TCP Probe (OPEN / CLOSED / TIMEOUT / ERROR)

[x] Phase 3: Sequential Multi-Port Scanner & Range Parser

[x] Phase 4: Two-Tier Service Identification (port-based guess & SSH/HTTP/PostgreSQL protocol probes)

[x] Phase 5: Structured Terminal Output System & Unified Report Model

[x] Phase 6: JSON Report Export with UTC Metadata

[x] Phase 7: Automated Unit Testing with Socket Mocking

[x] Phase 8: Portfolio Documentation