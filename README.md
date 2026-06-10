# Nitakusaka

**Automated reconnaissance framework for bug bounty hunters and penetration testers.**

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-In%20Development-orange)

---

## Overview

Nitakusaka automates the reconnaissance phase of a penetration test or bug bounty engagement.
Given a target domain, it performs the following:

- Subdomain enumeration via DNS brute-forcing
- Open port detection with service banner grabbing
- HTTP/S probing for status codes, page titles, and technology stacks
- Clean report generation in HTML and JSON format

---

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| `dns_module.py` | Subdomain enumeration via wordlist | In Progress |
| `port_module.py` | TCP port scanner with banner grabbing | Planned |
| `http_module.py` | HTTP prober and tech fingerprinting | Planned |
| `report_module.py` | HTML and JSON report generator | Planned |

---

## Installation

```bash
git clone https://github.com/Friendly-Neighbour24/Nitakusaka.git
cd Nitakusaka
pip install -r requirements.txt
```

---

## Usage

```bash
python nitakusaka.py --target example.com --module dns
```

*Full usage documentation will be updated as modules are completed.*

---

## Roadmap

- [x] Project structure
- [ ] DNS enumeration module
- [ ] Port scanner module
- [ ] HTTP prober module
- [ ] Report generator
- [ ] API integrations (Shodan, VirusTotal, crt.sh)

---

## Legal Disclaimer

This tool is intended for authorized security testing only.
Always obtain written permission before conducting reconnaissance on any target.
The author assumes no responsibility for unauthorized or illegal use.

---

## Author

**Hans** — [@Friendly-Neighbour24](https://github.com/Friendly-Neighbour24)