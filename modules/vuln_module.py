import subprocess
import json
import os
from datetime import datetime

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

NUCLEI_PATH = r"C:\Program Files\nuclei\nuclei.exe"
AMASS_PATH  = r"C:\Program Files\amass\amass.exe"

NUCLEI_TEMPLATE_SETS = {
    "owasp":        ["owasp-top-ten"],
    "cves":         ["cves"],
    "misconfig":    ["misconfiguration"],
    "exposed":      ["exposed-panels"],
    "takeover":     ["takeovers"],
    "default-creds":["default-credentials"],
    "full":         [
                        "owasp-top-ten",
                        "cves",
                        "misconfiguration",
                        "exposed-panels",
                        "takeovers",
                        "default-credentials",
                        "vulnerabilities",
                    ],
}

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

# ──────────────────────────────────────────────
#  AMASS INTEGRATION
# ──────────────────────────────────────────────

def run_amass(domain, output_dir="results"):
    """
    Run OWASP Amass for deep subdomain enumeration.
    Amass uses 50+ data sources including certificate
    transparency, DNS brute force, and OSINT sources.
    Complements our dns_module with passive intelligence.
    """
    if not os.path.exists(AMASS_PATH):
        print("[!] Amass not found — skipping")
        return []

    print(f"\n[*] Running Amass enumeration for {domain}...")
    print(f"    [*] This may take several minutes — Amass is thorough")

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"amass_{domain.replace('.','_')}_{timestamp}.txt"
    )

    cmd = [
        AMASS_PATH, "enum",
        "-d", domain,
        "-o", output_path,
        "-silent",
        "-timeout", "10",
    ]

    print(f"    [*] Command: {' '.join(cmd)}")

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=700
        )

        # Parse output file
        subdomains = []
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and domain in line:
                        subdomains.append(line)

        print(f"    [+] Amass found {len(subdomains)} subdomains")
        for sub in subdomains[:10]:
            print(f"        {sub}")
        if len(subdomains) > 10:
            print(f"        ... and {len(subdomains) - 10} more")

        return subdomains

    except subprocess.TimeoutExpired:
        print("[!] Amass timed out — returning partial results")
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                return [l.strip() for l in f if l.strip()]
        return []
    except Exception as e:
        print(f"[!] Amass failed: {e}")
        return []
    
    # ──────────────────────────────────────────────
#  NUCLEI INTEGRATION
# ──────────────────────────────────────────────

def run_nuclei(targets, template_set="owasp", output_dir="results"):
    """
    Run Nuclei vulnerability scanner against targets.
    template_set options: owasp, cves, misconfig,
                         exposed, takeover, default-creds, full
    targets: single URL, list of URLs, or path to targets file
    """
    if not os.path.exists(NUCLEI_PATH):
        print("[!] Nuclei not found — skipping")
        return []

    print(f"\n[*] Running Nuclei {template_set} scan...")

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"nuclei_{template_set}_{timestamp}.json"
    )

    # Write targets to temp file
    targets_file = os.path.join(output_dir, "nuclei_targets.txt")
    if isinstance(targets, list):
        with open(targets_file, "w") as f:
            for target in targets:
                f.write(target + "\n")
        input_arg = ["-l", targets_file]
    elif isinstance(targets, str) and os.path.exists(targets):
        input_arg = ["-l", targets]
    else:
        with open(targets_file, "w") as f:
            f.write(targets + "\n")
        input_arg = ["-l", targets_file]

    # Build template arguments
    templates = NUCLEI_TEMPLATE_SETS.get(template_set, ["owasp-top-ten"])
    template_args = []
    for template in templates:
        template_args.extend(["-tags", template])

    cmd = [
        NUCLEI_PATH,
        *input_arg,
        *template_args,
        "-je",   output_path,   # JSON export
        "-silent",              # no banner
        "-nc",                  # no color in output
        "-c",    "25",          # 25 concurrent templates
        "-rate-limit", "50",    # 50 requests per second
        "-timeout", "10",       # 10 second timeout per request
    ]

    print(f"    [*] Templates : {', '.join(templates)}")
    print(f"    [*] Rate limit: 50 req/s")

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )

        return parse_nuclei_output(output_path)

    except subprocess.TimeoutExpired:
        print("[!] Nuclei timed out — returning partial results")
        return parse_nuclei_output(output_path)
    except Exception as e:
        print(f"[!] Nuclei failed: {e}")
        return []


def parse_nuclei_output(output_path):
    """
    Parse Nuclei JSON output into our standard findings format.
    Handles both JSON array and JSONL formats.
    """
    findings = []

    if not os.path.exists(output_path):
        print(f"[!] Nuclei output not found at {output_path}")
        return findings

    try:
        with open(output_path, "r") as f:
            content = f.read().strip()

        if not content:
            print("[*] Nuclei found 0 vulnerabilities")
            return findings

        # Try JSON array first, fall back to JSONL
        try:
            data_list = json.loads(content)
            items = data_list if isinstance(data_list, list) else [data_list]
        except json.JSONDecodeError:
            items = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for data in items:
            severity = SEVERITY_MAP.get(
                data.get("info", {}).get("severity", "info"),
                "INFO"
            )
            finding = {
                "severity":       severity,
                "title":          data.get("info", {}).get("name", ""),
                "detail":         data.get("info", {}).get("description", ""),
                "template":       data.get("template-id", ""),
                "url":            data.get("matched-at", ""),
                "evidence": {
                    "matched_at": data.get("matched-at", ""),
                    "extracted":  data.get("extracted-results", []),
                    "curl":       data.get("curl-command", ""),
                },
                "tags":           data.get("info", {}).get("tags", []),
                "cve":            data.get("info", {}).get(
                                      "classification", {}
                                  ).get("cve-id", []),
                "recommendation": data.get("info", {}).get("remediation", ""),
                "source":         "nuclei",
            }
            findings.append(finding)
            cve_str = f" [{', '.join(finding['cve'])}]" if finding["cve"] else ""
            print(f"    [+] [{severity}] {finding['title']}{cve_str}")
            print(f"         URL: {finding['url']}")

        print(f"\n[*] Nuclei found {len(findings)} vulnerabilities")
        return findings

    except Exception as e:
        print(f"[!] Could not parse Nuclei output: {e}")
        return []
    
    # ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(domain, targets=None, template_set="owasp",
        run_amass=True, output_dir="results"):
    """
    Full vulnerability scanning pipeline:
      1. Amass deep subdomain enumeration
      2. Nuclei vulnerability scanning against all targets
      3. Correlate and save findings

    domain:       root domain to enumerate
    targets:      list of URLs to scan (from http_module)
                  if None, scans domain directly
    template_set: nuclei template set to use
    run_amass:    whether to run Amass enumeration first
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — VULNERABILITY MODULE")
    print(f"  Target      : {domain}")
    print(f"  Templates   : {template_set}")
    print(f"  Amass       : {'enabled' if run_amass else 'disabled'}")
    print(f"  Started     : "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    results = {
        "domain":       domain,
        "timestamp":    datetime.now().isoformat(),
        "amass":        [],
        "nuclei":       [],
        "total_findings": 0,
        "critical":     0,
        "high":         0,
        "medium":       0,
        "low":          0,
    }

    # 1. Amass enumeration
    if run_amass:
        amass_subdomains = run_amass_scan(domain, output_dir)
        results["amass"] = amass_subdomains

        # Add discovered subdomains to targets
        if amass_subdomains and targets is None:
            targets = [f"http://{sub}" for sub in amass_subdomains]
            targets.append(f"http://{domain}")
        elif amass_subdomains and isinstance(targets, list):
            targets.extend(
                [f"http://{sub}" for sub in amass_subdomains]
            )

    # 2. Build final targets list
    if targets is None:
        targets = [f"http://{domain}", f"https://{domain}"]
    elif isinstance(targets, str):
        targets = [targets]

    # Deduplicate targets
    targets = list(dict.fromkeys(targets))
    print(f"\n[*] Total targets for Nuclei: {len(targets)}")

    # 3. Run Nuclei
    nuclei_findings = run_nuclei(targets, template_set, output_dir)
    results["nuclei"] = nuclei_findings

    # 4. Count by severity
    for finding in nuclei_findings:
        severity = finding.get("severity", "INFO")
        if severity == "CRITICAL":
            results["critical"] += 1
        elif severity == "HIGH":
            results["high"] += 1
        elif severity == "MEDIUM":
            results["medium"] += 1
        elif severity == "LOW":
            results["low"] += 1

    results["total_findings"] = len(nuclei_findings)

    # 5. Print summary
    print(f"\n{'='*60}")
    print(f"  VULNERABILITY SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Subdomains found (Amass) : {len(results['amass'])}")
    print(f"  Vulnerabilities found    : {results['total_findings']}")
    print(f"  Critical                 : {results['critical']}")
    print(f"  High                     : {results['high']}")
    print(f"  Medium                   : {results['medium']}")
    print(f"  Low                      : {results['low']}")
    print(f"{'='*60}")

    # 6. Save results
    os.makedirs(output_dir, exist_ok=True)
    safe_domain = domain.replace(".", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"vuln_{safe_domain}_{timestamp}.json"
    )

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    return results


# Alias to avoid naming conflict with run_amass function
def run_amass_scan(domain, output_dir):
    return run_amass(domain, output_dir)

