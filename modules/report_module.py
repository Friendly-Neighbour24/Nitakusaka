import json
import os
import glob
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "../templates")
RESULTS_DIR   = "results"

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLORS = {
    "CRITICAL": "#FF3366",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB800",
    "LOW":      "#00C8FF",
    "INFO":     "#7A8AAA",
}

# ──────────────────────────────────────────────
#  RESULTS LOADER
# ──────────────────────────────────────────────

def load_latest_results(results_dir=RESULTS_DIR):
    """
    Load the most recent result file from each module.
    Returns a unified data dictionary for the report.
    """
    print(f"\n[*] Loading scan results from {results_dir}...")

    data = {
        "dns":        None,
        "ports":      None,
        "http":       None,
        "correlator": None,
        "vuln":       None,
        "reverse":    None,
        "content":    None,
    }

    # Map of module prefix to data key
    module_files = {
        "dns_":        "dns",
        "ports_":      "ports",
        "http_":       "http",
        "correlator_": "correlator",
        "vuln_":       "vuln",
        "reverse_":    "reverse",
        "content_":    "content",
    }

    for prefix, key in module_files.items():
        pattern = os.path.join(results_dir, f"{prefix}*.json")
        files   = sorted(glob.glob(pattern))
        if files:
            latest = files[-1]
            try:
                with open(latest, "r") as f:
                    data[key] = json.load(f)
                print(f"    [+] Loaded {key}: {os.path.basename(latest)}")
            except Exception as e:
                print(f"    [!] Could not load {key}: {e}")
        else:
            print(f"    [-] No {key} results found")

    return data


def load_specific_results(dns=None, ports=None, http=None,
                          correlator=None, vuln=None):
    """
    Load specific result files by path.
    Use this when you want to report on a specific scan
    rather than the latest results.
    """
    data = {}

    for key, path in [("dns", dns), ("ports", ports),
                      ("http", http), ("correlator", correlator),
                      ("vuln", vuln)]:
        if path and os.path.exists(path):
            with open(path, "r") as f:
                data[key] = json.load(f)
        else:
            data[key] = None

    return data

# ──────────────────────────────────────────────
#  REPORT DATA BUILDER
# ──────────────────────────────────────────────

def build_report_data(data):
    """
    Transform raw module results into a unified structure
    ready for the report template. Aggregates all findings,
    counts severities, and organizes everything cleanly.
    """
    print(f"\n[*] Building report data...")

    # Determine target
    target = "Unknown"
    if data.get("dns"):
        target = data["dns"].get("target", "Unknown")
    elif data.get("ports"):
        target = data["ports"].get("target", "Unknown")
    elif data.get("vuln"):
        target = data["vuln"].get("domain", "Unknown")

    report = {
        "target":        target,
        "generated":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool":          "Nitakusaka",
        "version":       "1.0",
        "findings":      [],
        "subdomains":    [],
        "open_ports":    [],
        "technologies":  set(),
        "reverse_hosts": [],
        "content_paths": [],
        "severity_counts": {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
            "LOW": 0, "INFO": 0
        },
    }

    # Aggregate all findings from correlator
    if data.get("correlator"):
        for finding in data["correlator"].get("findings", []):
            report["findings"].append(finding)

    # Aggregate all findings from vuln module (nuclei)
    if data.get("vuln"):
        for finding in data["vuln"].get("nuclei", []):
            report["findings"].append(finding)

    # Count severities
    for finding in report["findings"]:
        severity = finding.get("severity", "INFO")
        if severity in report["severity_counts"]:
            report["severity_counts"][severity] += 1

    # Sort findings by severity
    report["findings"].sort(
        key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)
    )

    # Collect subdomains
    if data.get("dns"):
        for sub in data["dns"].get("subdomains", []):
            report["subdomains"].append({
                "subdomain": sub.get("subdomain", ""),
                "ips":       ", ".join(sub.get("ips", [])),
                "status":    sub.get("status", ""),
            })

    # Add Amass subdomains
    if data.get("vuln"):
        for sub in data["vuln"].get("amass", []):
            if not any(s["subdomain"] == sub
                      for s in report["subdomains"]):
                report["subdomains"].append({
                    "subdomain": sub,
                    "ips":       "",
                    "status":    "amass",
                })

    # Collect open ports
    if data.get("ports"):
        for port in data["ports"].get("open_ports", []):
            report["open_ports"].append({
                "port":    port.get("port", ""),
                "service": port.get("service", ""),
                "banner":  (port.get("banner") or "")[:100],
                "risk":    port.get("risk") or "",
            })

    # Collect technologies from HTTP results
    if data.get("http"):
        for host in data["http"].get("results", []):
            for tech in host.get("technologies", []):
                report["technologies"].add(tech)

    # Convert set to sorted list for template
    report["technologies"] = sorted(list(report["technologies"]))

    # Collect reverse DNS hosts
    if data.get("reverse"):
        for host in data["reverse"].get("hostnames", []):
            hostname = host.get("hostname", "")
            parts = hostname.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            report["reverse_hosts"].append({
                "ip":       host.get("ip", ""),
                "hostname": hostname,
                "root":     root,
            })

    # Collect content discovery paths
    if data.get("content"):
        for item in data["content"].get("discovered", []):
            report["content_paths"].append({
                "url":         item.get("url", ""),
                "path":        item.get("path", ""),
                "status_code": item.get("status_code", ""),
                "severity":    item.get("severity") or "",
            })        

    # Summary stats
    report["total_findings"]   = len(report["findings"])
    report["total_subdomains"] = len(report["subdomains"])
    report["total_ports"]      = len(report["open_ports"])

    print(f"    [+] Target: {report['target']}")
    print(f"    [+] Findings: {report['total_findings']}")
    print(f"    [+] Subdomains: {report['total_subdomains']}")
    print(f"    [+] Open ports: {report['total_ports']}")

    return report

# ──────────────────────────────────────────────
#  HTML REPORT GENERATOR
# ──────────────────────────────────────────────

def generate_html_report(report, output_dir=RESULTS_DIR):
    """
    Render the HTML report using the Jinja2 template.
    """
    print(f"\n[*] Generating HTML report...")

    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    env.globals["severity_colors"] = SEVERITY_COLORS

    try:
        template = env.get_template("report.html.j2")
    except Exception as e:
        print(f"[!] Could not load template: {e}")
        return None

    html = template.render(report=report)

    safe_target = report["target"].replace(".", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"report_{safe_target}_{timestamp}.html"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"    [+] HTML report saved to {output_path}")
    return output_path


# ──────────────────────────────────────────────
#  MARKDOWN REPORT GENERATOR
# ──────────────────────────────────────────────

def generate_markdown_report(report, output_dir=RESULTS_DIR):
    """
    Generate a markdown report for bug bounty submissions
    and GitHub documentation.
    """
    print(f"\n[*] Generating Markdown report...")

    md = []
    md.append(f"# Nitakusaka Recon Report — {report['target']}\n")
    md.append(f"**Generated:** {report['generated']}  ")
    md.append(f"**Tool:** {report['tool']} v{report['version']}\n")
    md.append("---\n")

    # Executive summary
    md.append("## Executive Summary\n")
    md.append(f"- **Total Findings:** {report['total_findings']}")
    md.append(f"- **Subdomains Discovered:** {report['total_subdomains']}")
    md.append(f"- **Open Ports:** {report['total_ports']}\n")

    counts = report["severity_counts"]
    md.append("### Findings by Severity\n")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        md.append(f"| {sev} | {counts[sev]} |")
    md.append("")

    # Findings
    if report["findings"]:
        md.append("## Findings\n")
        for i, finding in enumerate(report["findings"], 1):
            md.append(f"### {i}. [{finding['severity']}] "
                     f"{finding.get('title', 'Untitled')}\n")
            md.append(f"{finding.get('detail', '')}\n")
            if finding.get("url"):
                md.append(f"**URL:** `{finding['url']}`\n")
            if finding.get("cve"):
                cves = ", ".join(finding["cve"]) if isinstance(
                    finding["cve"], list) else finding["cve"]
                if cves:
                    md.append(f"**CVE:** {cves}\n")
            if finding.get("recommendation"):
                md.append(f"**Recommendation:** "
                         f"{finding['recommendation']}\n")
            md.append("")

    # Subdomains
    if report["subdomains"]:
        md.append("## Discovered Subdomains\n")
        md.append("| Subdomain | IPs | Status |")
        md.append("|-----------|-----|--------|")
        for sub in report["subdomains"]:
            md.append(f"| {sub['subdomain']} | {sub['ips']} "
                     f"| {sub['status']} |")
        md.append("")

    # Open ports
    if report["open_ports"]:
        md.append("## Open Ports\n")
        md.append("| Port | Service | Risk |")
        md.append("|------|---------|------|")
        for port in report["open_ports"]:
            md.append(f"| {port['port']} | {port['service']} "
                     f"| {port['risk']} |")
        md.append("")

    # Technologies
    if report["technologies"]:
        md.append("## Detected Technologies\n")
        for tech in report["technologies"]:
            md.append(f"- {tech}")
        md.append("")

    md.append("---")
    md.append(f"*Report generated by Nitakusaka — "
             f"automated recon framework*")

    markdown_content = "\n".join(md)

    safe_target = report["target"].replace(".", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"report_{safe_target}_{timestamp}.md"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"    [+] Markdown report saved to {output_path}")
    return output_path


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(formats=None, output_dir=RESULTS_DIR, **specific_files):
    """
    Generate reports from scan results.
    formats: list of formats to generate
             options: 'html', 'markdown', 'json'
             default: all three
    specific_files: optionally pass dns=, ports=, http=,
                    correlator=, vuln= paths to report on
                    specific scans
    """
    if formats is None:
        formats = ["html", "markdown", "json"]

    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — REPORT GENERATOR")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Load results
    if specific_files:
        data = load_specific_results(**specific_files)
    else:
        data = load_latest_results(output_dir)

    # Build report data
    report = build_report_data(data)

    # Generate requested formats
    outputs = {}

    if "html" in formats:
        outputs["html"] = generate_html_report(report, output_dir)

    if "markdown" in formats:
        outputs["markdown"] = generate_markdown_report(report, output_dir)

    if "json" in formats:
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = report["target"].replace(".", "_")
        json_path   = os.path.join(
            output_dir, f"report_{safe_target}_{timestamp}.json"
        )
        # Convert set to list for JSON serialization
        report_copy = dict(report)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_copy, f, indent=4, default=str)
        outputs["json"] = json_path
        print(f"\n[*] JSON report saved to {json_path}")

    print(f"\n{'='*60}")
    print(f"  REPORT GENERATION COMPLETE")
    for fmt, path in outputs.items():
        if path:
            print(f"  {fmt.upper():<10} → {path}")
    print(f"{'='*60}\n")

    return outputs


# ----------------------------------------------
#  CHANGE REPORT GENERATOR (for monitor module)
# ----------------------------------------------

def generate_change_report(changes, target, output_dir=RESULTS_DIR):
    """Generate an HTML change report from monitor output."""
    print("\n[*] Generating HTML change report...")
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    try:
        template = env.get_template("changes.html.j2")
    except Exception as e:
        print("[!] Could not load change template:", e)
        return None
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = template.render(target=target, generated=generated, changes=changes)
    safe_target = target.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, "changes_" + safe_target + "_" + timestamp + ".html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("    [+] Change report saved to", output_path)
    return output_path

