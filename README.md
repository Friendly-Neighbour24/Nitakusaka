# Nitakusaka

**Automated offensive reconnaissance framework built for African infrastructure and bug bounty hunters.**

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-v1.3-brightgreen)
![Focus](https://img.shields.io/badge/Focus-African%20Infrastructure-red)
![PRs](https://img.shields.io/badge/PRs-welcome-orange)

---

## Overview

Nitakusaka (Swahili: *"I will make it"*) automates the full reconnaissance phase of a penetration test or bug bounty engagement. Unlike generic recon tools built for Western infrastructure, Nitakusaka is designed with awareness of African CDNs, hosting providers, mobile money platforms, and regional TLDs (.co.tz, .co.ke, .ng).

Give it a target domain and it enumerates subdomains, scans for open ports, probes live HTTP/S hosts, fingerprints technologies, discovers hidden content, scans for vulnerabilities, correlates the findings into actionable intelligence, and generates a professional report — all from a single command.

```bash
python nitakusaka.py --target example.com --full
```

---

## What makes it different

Most recon tools hand you a list of findings and stop there. Nitakusaka goes further:

**Contextual wordlists** — instead of blasting the same generic wordlist every tool uses, Nitakusaka generates target-specific subdomain guesses based on the company's industry and region. A built-in local engine works out of the box with no API key, producing region-aware terms like `wakala`, `benki`, and `mpesa-gateway` against a Tanzanian bank. When an Anthropic API key is provided, it layers AI-generated guesses on top for even deeper coverage.

**Automatic correlation** — findings from every module are cross-referenced against known vulnerability patterns automatically. An open database port combined with a sensitive subdomain gets flagged as a compound finding a single scanner would miss.

**African infrastructure awareness** — built-in knowledge of regional hosting providers, mobile money platforms (M-Pesa, Airtel Money, MTN MoMo), and African TLDs that generic tools overlook. Works on any target worldwide, but smarter on African ones.

**Industry-standard tool integration** — wraps Nmap, httpx, Nuclei, OWASP Amass, and ffuf under one unified interface and reporting pipeline.

**Continuous monitoring** — a watch mode that re-scans on a schedule and alerts on changes to the target's attack surface: new subdomains, newly opened ports, and more.

**Three audiences, one scan** — raw JSON for pipelines, polished HTML for portfolio and clients, markdown for bug bounty submissions.

---

## Architecture

```
                       nitakusaka.py (CLI)
                              |
     +------------+-----------+-----------+-------------+
     v            v           v           v             v
 DNS Module   Port Module  HTTP Module  Content      Reverse DNS
 + zone xfer  + Nmap       + httpx      Discovery    (IP/CIDR/ASN)
 + wordlist   + banners    + fingerprint + ffuf
     |            |           |           |
     +------------+-----------+-----------+
                              v
                        Vuln Module
                        + Nuclei (9000+ templates)
                        + OWASP Amass
                              v
                        Correlator
                        (cross-references all findings)
                              v
                        Report Module
                        HTML / Markdown / JSON
                              v
                        Monitor Module
                        (continuous change detection)
```

---

## Modules

| Module | Description | Integrations |
|--------|-------------|--------------|
| `dns_module.py` | Subdomain enumeration + zone transfer attempts | dnspython |
| `ai_wordlist.py` | Contextual subdomain wordlists (local + optional AI) | Anthropic API |
| `port_module.py` | TCP port scanner with banner grabbing | Nmap |
| `http_module.py` | HTTP prober and technology fingerprinting | httpx |
| `content_module.py` | Directory and file content discovery | ffuf |
| `vuln_module.py` | Vulnerability scanning + deep enumeration | Nuclei, Amass |
| `reverse_dns.py` | Reverse DNS from IP, CIDR block, or range | — |
| `correlator.py` | Automatic vulnerability correlation engine | — |
| `monitor.py` | Continuous attack surface change detection | — |
| `report_module.py` | HTML, Markdown, and JSON report generation | Jinja2 |

---

## Installation

```bash
git clone https://github.com/Friendly-Neighbour24/Nitakusaka.git
cd Nitakusaka
pip install -r requirements.txt
```

### Optional external tools

Nitakusaka works out of the box with its built-in Python engines. For full power, install these industry-standard tools — Nitakusaka detects and uses them automatically when present:

- [Nmap](https://nmap.org/download.html) — advanced port scanning
- [httpx](https://github.com/projectdiscovery/httpx) — fast HTTP probing
- [ffuf](https://github.com/ffuf/ffuf) — content/directory discovery
- [Nuclei](https://github.com/projectdiscovery/nuclei) — vulnerability scanning
- [OWASP Amass](https://github.com/owasp-amass/amass) — deep subdomain enumeration

After installing the Go-based tools (httpx, ffuf, Nuclei, Amass), ensure their binaries are on your system PATH, or update the path constants at the top of the relevant module. On Windows, Defender may flag offensive tools as false positives — add a folder exclusion if needed.

### Wordlists

Nitakusaka uses [SecLists](https://github.com/danielmiessler/SecLists). Download the subdomain and directory wordlists into the `wordlists/` directory:

```bash
curl -o wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
curl -o wordlists/directories.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
```

### AI wordlist setup (optional)

The contextual wordlist engine works without any API key. To additionally enable AI-generated wordlists, set an Anthropic API key:

```bash
# Create a .env file (never commit this)
echo ANTHROPIC_API_KEY=your_key_here > .env
```

---

## Usage

```bash
# Full recon pipeline
python nitakusaka.py --target example.com --full

# Single modules
python nitakusaka.py --target example.com --module dns
python nitakusaka.py --target example.com --module ports --use-nmap
python nitakusaka.py --target example.com --module http
python nitakusaka.py --target example.com --module content
python nitakusaka.py --target example.com --module vuln --templates owasp

# DNS with contextual wordlist
python nitakusaka.py --target example.com --module dns --ai-wordlist

# Reverse DNS on an IP, CIDR block, or range
python nitakusaka.py --reverse 196.216.10.0/24

# Continuous monitoring
python nitakusaka.py --target example.com --watch --interval 3600

# Single monitoring check against the last snapshot
python nitakusaka.py --target example.com --monitor

# Control report format
python nitakusaka.py --target example.com --full --report-format html
```

Run `python nitakusaka.py --help` for the complete list of options.

---

## Sample Report

Nitakusaka generates a professional HTML report with an executive summary, color-coded findings by severity, discovered subdomains, open ports with risk assessment, content discovery results, reverse DNS infrastructure mapping, and detected technologies.

![Nitakusaka Report](docs/report-screenshot.png)

---

## Roadmap

- [x] DNS enumeration module
- [x] Contextual wordlist generator (local + AI)
- [x] Port scanner with Nmap integration
- [x] HTTP prober with httpx integration
- [x] Content discovery with ffuf integration
- [x] Vulnerability scanning with Nuclei + Amass
- [x] Reverse DNS / CIDR / range enumeration
- [x] Correlation engine
- [x] Continuous monitoring mode
- [x] Multi-format report generator
- [x] Unified CLI
- [ ] Attack path visualization
- [ ] African infrastructure signature database expansion

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain explicit written permission before conducting reconnaissance against any target you do not own. Unauthorized scanning may be illegal in your jurisdiction. The author assumes no responsibility for misuse or for any damage caused by this tool. Use it ethically and responsibly.

When testing, use authorized targets such as [scanme.nmap.org](http://scanme.nmap.org) or systems within an active bug bounty program scope.

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the issues page.

---

## Author

**Hans** — [@Friendly-Neighbour24](https://github.com/Friendly-Neighbour24)

Built as a portfolio project to demonstrate offensive security tooling, Python engineering, and automation design.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
