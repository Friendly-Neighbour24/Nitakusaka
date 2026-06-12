import json
import os
from datetime import datetime

# ──────────────────────────────────────────────
#  CORRELATION RULES
# ──────────────────────────────────────────────

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

# Services that should never be publicly exposed
CRITICAL_EXPOSED_SERVICES = {
    2375:  "Docker API exposed — full container takeover possible",
    6379:  "Redis exposed — likely unauthenticated access to all data",
    6380:  "Redis exposed — likely unauthenticated access to all data",
    9200:  "Elasticsearch exposed — likely unauthenticated data access",
    9300:  "Elasticsearch exposed — likely unauthenticated data access",
    11211: "Memcached exposed — DDoS amplification and data exposure",
    27017: "MongoDB exposed — likely unauthenticated database access",
    5432:  "PostgreSQL exposed publicly — credential brute force risk",
    1433:  "MSSQL exposed publicly — credential brute force risk",
    3306:  "MySQL exposed publicly — credential brute force risk",
}

# Subdomain patterns that suggest sensitive infrastructure
SENSITIVE_SUBDOMAIN_PATTERNS = [
    "admin", "administrator", "portal", "dashboard",
    "dev", "development", "staging", "test", "uat",
    "api", "backend", "internal", "intranet",
    "vpn", "remote", "access", "secure",
    "db", "database", "mysql", "mongo",
    "jenkins", "gitlab", "jira", "confluence",
    "backup", "old", "legacy", "temp",
]

# Technology + path combinations that are critical
CRITICAL_COMBINATIONS = [
    {
        "condition": "phpmyadmin_in_title",
        "severity":  SEVERITY_CRITICAL,
        "title":     "phpMyAdmin Exposed",
        "detail":    "phpMyAdmin interface publicly accessible — "
                     "direct database access possible",
    },
    {
        "condition": "git_exposed",
        "severity":  SEVERITY_CRITICAL,
        "title":     "Git Repository Exposed",
        "detail":    "/.git directory accessible — full source "
                     "code disclosure possible",
    },
    {
        "condition": "env_exposed",
        "severity":  SEVERITY_CRITICAL,
        "title":     "Environment File Exposed",
        "detail":    "/.env file accessible — credentials and API "
                     "keys likely exposed",
    },
    {
        "condition": "docker_api_exposed",
        "severity":  SEVERITY_CRITICAL,
        "title":     "Docker API Exposed",
        "detail":    "Docker daemon API accessible — full container "
                     "and host takeover possible",
    },
]

# Known subdomain takeover vulnerable services
TAKEOVER_VULNERABLE_CNAMES = [
    "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "s3.amazonaws.com", "github.io", "herokuapp.com",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
    "zendesk.com", "freshdesk.com", "helpscoutdocs.com",
    "ghost.io", "wishpond.com", "aftership.com",
    "cargo.site", "tumblr.com", "wordpress.com",
]

# ──────────────────────────────────────────────
#  CORRELATION ENGINE
# ──────────────────────────────────────────────

def correlate_dns_and_ports(dns_results, port_results):
    """
    Cross-reference DNS subdomains with open ports.
    Flags sensitive subdomains with dangerous open ports.
    """
    findings = []

    if not dns_results or not port_results:
        return findings

    subdomains = dns_results.get("subdomains", [])
    open_ports = port_results.get("open_ports", [])
    open_port_numbers = [p["port"] for p in open_ports]

    # Check for critically exposed services
    for port in open_ports:
        if port["port"] in CRITICAL_EXPOSED_SERVICES:
            findings.append({
                "severity": SEVERITY_CRITICAL,
                "title":    f"Critical Service Exposed: "
                           f"{port['service']} on port {port['port']}",
                "detail":   CRITICAL_EXPOSED_SERVICES[port["port"]],
                "evidence": {
                    "port":    port["port"],
                    "service": port["service"],
                    "banner":  port.get("banner", None),
                },
                "recommendation": "Immediately restrict access to this "
                                 "port using firewall rules. This service "
                                 "should never be publicly accessible."
            })

    # Check sensitive subdomains
    for subdomain in subdomains:
        name = subdomain["subdomain"].split(".")[0].lower()
        for pattern in SENSITIVE_SUBDOMAIN_PATTERNS:
            if pattern in name:
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "title":    f"Sensitive Subdomain Exposed: "
                               f"{subdomain['subdomain']}",
                    "detail":   f"Subdomain matching pattern '{pattern}' "
                               f"is publicly accessible",
                    "evidence": {
                        "subdomain": subdomain["subdomain"],
                        "ips":       subdomain.get("ips", []),
                        "pattern":   pattern,
                    },
                    "recommendation": "Verify this subdomain should be "
                                     "publicly accessible. Consider moving "
                                     "to internal DNS if not needed publicly."
                })
                break

    return findings


def correlate_http_findings(http_results):
    """
    Analyze HTTP results for security issues.
    Flags missing security headers, exposed admin panels,
    sensitive files, and technology-specific vulnerabilities.
    """
    findings = []

    if not http_results:
        return findings

    results = http_results.get("results", [])

    for host in results:
        url   = host.get("url", "")
        title = (host.get("title") or "").lower()
        paths = host.get("interesting_paths", [])
        techs = host.get("technologies", [])
        headers = host.get("security_headers", {})

        # Check for exposed sensitive paths
        for path in paths:
            if path.get("severity") == "CRITICAL":
                condition = None
                if "/.git" in path["path"]:
                    condition = "git_exposed"
                elif "/.env" in path["path"]:
                    condition = "env_exposed"

                if condition:
                    for combo in CRITICAL_COMBINATIONS:
                        if combo["condition"] == condition:
                            findings.append({
                                "severity": combo["severity"],
                                "title":    combo["title"],
                                "detail":   combo["detail"],
                                "evidence": {
                                    "url":         url,
                                    "path":        path["path"],
                                    "status_code": path["status_code"],
                                },
                                "recommendation": "Immediately restrict "
                                                 "access to this path and "
                                                 "rotate any exposed credentials."
                            })

        # Check for phpMyAdmin
        if "phpmyadmin" in title or "phpmyadmin" in url.lower():
            findings.append({
                "severity": SEVERITY_CRITICAL,
                "title":    "phpMyAdmin Exposed",
                "detail":   "phpMyAdmin interface publicly accessible",
                "evidence": {"url": url, "title": title},
                "recommendation": "Restrict phpMyAdmin to internal "
                                 "network access only."
            })

        # Check missing security headers
        missing_headers = [
            h for h, v in headers.items() if not v["present"]
        ]
        if missing_headers:
            severity = (SEVERITY_MEDIUM if len(missing_headers) >= 3
                       else SEVERITY_LOW)
            findings.append({
                "severity": severity,
                "title":    f"Missing Security Headers on {url}",
                "detail":   f"{len(missing_headers)} security headers "
                           f"not configured",
                "evidence": {
                    "url":             url,
                    "missing_headers": missing_headers,
                },
                "recommendation": "Implement missing security headers "
                                 "in the web server configuration."
            })

        # Check for old/vulnerable technologies
        for tech in techs:
            if "Apache/2.4.7" in tech or "Apache/2.2" in tech:
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "title":    f"Outdated Apache Version Detected",
                    "detail":   f"Apache version detected may have "
                               f"known vulnerabilities",
                    "evidence": {"url": url, "technology": tech},
                    "recommendation": "Update Apache to the latest "
                                     "stable version immediately."
                })

    return findings


def correlate_subdomain_takeover(dns_results, http_results):
    """
    Detect potential subdomain takeover vulnerabilities.
    A subdomain with a CNAME pointing to an unclaimed
    third-party service can be taken over by an attacker.
    """
    findings = []

    if not http_results:
        return findings

    results = http_results.get("results", [])

    for host in results:
        cnames = host.get("cname", [])
        for cname in cnames:
            for vulnerable_service in TAKEOVER_VULNERABLE_CNAMES:
                if vulnerable_service in cname:
                    # Check if the host returns an error
                    # suggesting the service is unclaimed
                    status = host.get("status_code", 200)
                    if status in [404, 503, None]:
                        findings.append({
                            "severity": SEVERITY_HIGH,
                            "title":    "Potential Subdomain Takeover",
                            "detail":   f"CNAME points to {cname} which "
                                       f"may be unclaimed on "
                                       f"{vulnerable_service}",
                            "evidence": {
                                "url":         host.get("url"),
                                "cname":       cname,
                                "status_code": status,
                                "service":     vulnerable_service,
                            },
                            "recommendation": "Verify if the third-party "
                                            "service is still active. If not, "
                                            "remove the CNAME record immediately."
                        })

    return findings

# ──────────────────────────────────────────────
#  SEVERITY SORTER
# ──────────────────────────────────────────────

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH:     1,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      3,
    SEVERITY_INFO:     4,
}

def sort_findings(findings):
    """
    Sort findings by severity — critical first.
    """
    return sorted(
        findings,
        key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)
    )


def print_findings(findings):
    """
    Print findings to terminal in a clean format.
    """
    if not findings:
        print("\n[*] No findings to correlate.")
        return

    severity_colors = {
        SEVERITY_CRITICAL: "⚠ CRITICAL",
        SEVERITY_HIGH:     "▲ HIGH",
        SEVERITY_MEDIUM:   "● MEDIUM",
        SEVERITY_LOW:      "○ LOW",
        SEVERITY_INFO:     "  INFO",
    }

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n{'='*60}")
    print(f"  FINDINGS SUMMARY")
    print(f"{'='*60}")
    for severity, count in counts.items():
        if count > 0:
            print(f"  {severity_colors[severity]:<20} {count} finding(s)")
    print(f"{'='*60}\n")

    for finding in findings:
        label = severity_colors.get(finding["severity"], "  INFO")
        print(f"[{label}] {finding['title']}")
        print(f"  Detail : {finding['detail']}")
        if "recommendation" in finding:
            print(f"  Fix    : {finding['recommendation']}")
        print()


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(dns_results=None, port_results=None,
        http_results=None, output_dir="results"):
    """
    Run all correlation checks against available
    module results. Accepts results dicts directly
    or paths to JSON result files.
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — CORRELATOR MODULE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Load results from files if paths provided
    def load_result(result):
        if isinstance(result, str) and os.path.exists(result):
            with open(result, "r") as f:
                return json.load(f)
        return result

    dns_results  = load_result(dns_results)
    port_results = load_result(port_results)
    http_results = load_result(http_results)

    all_findings = []

    # Run all correlation checks
    print("\n[*] Running correlation checks...")

    dns_port_findings = correlate_dns_and_ports(
        dns_results, port_results
    )
    print(f"    [+] DNS + Port correlations: "
          f"{len(dns_port_findings)} findings")
    all_findings.extend(dns_port_findings)

    http_findings = correlate_http_findings(http_results)
    print(f"    [+] HTTP correlations: "
          f"{len(http_findings)} findings")
    all_findings.extend(http_findings)

    takeover_findings = correlate_subdomain_takeover(
        dns_results, http_results
    )
    print(f"    [+] Subdomain takeover checks: "
          f"{len(takeover_findings)} findings")
    all_findings.extend(takeover_findings)

    # Sort by severity
    all_findings = sort_findings(all_findings)

    # Print to terminal
    print_findings(all_findings)

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"correlator_{timestamp}.json"
    )

    final_results = {
        "timestamp":     datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "critical":      len([f for f in all_findings
                             if f["severity"] == SEVERITY_CRITICAL]),
        "high":          len([f for f in all_findings
                             if f["severity"] == SEVERITY_HIGH]),
        "medium":        len([f for f in all_findings
                             if f["severity"] == SEVERITY_MEDIUM]),
        "low":           len([f for f in all_findings
                             if f["severity"] == SEVERITY_LOW]),
        "findings":      all_findings,
    }

    with open(output_path, "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"[*] Correlator results saved to {output_path}")
    print(f"{'='*60}\n")

    return final_results
