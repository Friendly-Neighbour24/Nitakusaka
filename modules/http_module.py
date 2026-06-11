import requests
import json
import os
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# Suppress SSL warnings for misconfigured certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

DEFAULT_THREADS  = 50
REQUEST_TIMEOUT  = 5
MAX_REDIRECTS    = 5

INTERESTING_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin",
    "/phpmyadmin", "/cpanel", "/dashboard", "/portal",
    "/api", "/api/v1", "/api/v2", "/swagger",
    "/robots.txt", "/.env", "/config.php",
    "/backup", "/test", "/dev", "/staging",
    "/.git/HEAD", "/server-status", "/elmah.axd",
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP":          "PHP",
            "ASP.NET":      "ASP.NET",
            "Express":      "Node.js/Express",
        },
        "Server": {
            "Apache":       "Apache",
            "nginx":        "Nginx",
            "IIS":          "Microsoft IIS",
            "LiteSpeed":    "LiteSpeed",
            "cloudflare":   "Cloudflare",
        },
        "X-Generator": {
            "WordPress":    "WordPress",
            "Drupal":       "Drupal",
            "Joomla":       "Joomla",
        },
    },
    "html": {
        "wp-content":           "WordPress",
        "wp-includes":          "WordPress",
        "Drupal.settings":      "Drupal",
        "joomla":               "Joomla",
        "laravel_session":      "Laravel",
        "csrfmiddlewaretoken":  "Django",
        "react":                "React",
        "ng-version":           "Angular",
        "__nuxt":               "Nuxt.js",
        "__next":               "Next.js",
        "jquery":               "jQuery",
        "bootstrap":            "Bootstrap",
    },
    "cookies": {
        "PHPSESSID":        "PHP",
        "JSESSIONID":       "Java",
        "ASP.NET_SessionId":"ASP.NET",
        "laravel_session":  "Laravel",
        "django_session":   "Django",
    }
}

# ──────────────────────────────────────────────
#  TECH FINGERPRINTER
# ──────────────────────────────────────────────

def fingerprint_tech(response):
    """
    Detect technologies from HTTP response headers,
    HTML content, and cookies.
    Returns a list of detected technologies.
    """
    detected = set()

    # Check headers
    for header, patterns in TECH_SIGNATURES["headers"].items():
        header_value = response.headers.get(header, "")
        for pattern, tech in patterns.items():
            if pattern.lower() in header_value.lower():
                detected.add(tech)

    # Check HTML content
    try:
        html = response.text.lower()
        for pattern, tech in TECH_SIGNATURES["html"].items():
            if pattern.lower() in html:
                detected.add(tech)
    except Exception:
        pass

    # Check cookies
    for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
        if cookie_name in response.cookies:
            detected.add(tech)

    return list(detected)


# ──────────────────────────────────────────────
#  SECURITY HEADER CHECKER
# ──────────────────────────────────────────────

def check_security_headers(response):
    """
    Check for presence or absence of security headers.
    Missing headers are reportable findings in bug bounty.
    Returns dict of header -> present/missing.
    """
    results = {}
    for header in SECURITY_HEADERS:
        results[header] = {
            "present": header in response.headers,
            "value":   response.headers.get(header, None)
        }
    return results


# ──────────────────────────────────────────────
#  INTERESTING PATH CHECKER
# ──────────────────────────────────────────────

def check_interesting_paths(base_url, session):
    """
    Check a list of sensitive paths on the target.
    Flags anything that returns 200 or 403
    (403 means it exists but is protected — still interesting)
    """
    findings = []

    for path in INTERESTING_PATHS:
        url = base_url.rstrip("/") + path
        try:
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False
            )

            if response.status_code in [200, 403, 401, 301, 302]:
                finding = {
                    "path":        path,
                    "url":         url,
                    "status_code": response.status_code,
                    "size":        len(response.content),
                }

                # Flag high value findings
                if path in ["/.env", "/.git/HEAD", "/config.php"]:
                    finding["severity"] = "CRITICAL"
                elif path in ["/admin", "/phpmyadmin", "/wp-admin"]:
                    finding["severity"] = "HIGH"
                else:
                    finding["severity"] = "INFO"

                findings.append(finding)
                severity = finding.get("severity", "INFO")
                print(f"    [+] {response.status_code} "
                      f"{path:<30} [{severity}]")

        except Exception:
            pass

    return findings

# ──────────────────────────────────────────────
#  SINGLE HOST PROBER
# ──────────────────────────────────────────────

def probe_host(host, session):
    """
    Probe a single host for HTTP and HTTPS.
    Tries HTTPS first, falls back to HTTP.
    Returns full result dict or None if unreachable.
    """
    result = {
        "host":              host,
        "url":               None,
        "status_code":       None,
        "title":             None,
        "technologies":      [],
        "security_headers":  {},
        "interesting_paths": [],
        "flags":             [],
        "server":            None,
        "content_length":    None,
    }

    # Try HTTPS first then HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            response = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True
            )

            result["url"]            = response.url
            result["status_code"]    = response.status_code
            result["server"]         = response.headers.get("Server", None)
            result["content_length"] = len(response.content)

            # Extract page title
            try:
                soup  = BeautifulSoup(response.text, "html.parser")
                title = soup.find("title")
                result["title"] = title.get_text().strip() if title else None
            except Exception:
                pass

            # Fingerprint technologies
            result["technologies"] = fingerprint_tech(response)

            # Check security headers
            result["security_headers"] = check_security_headers(response)

            # Count missing security headers
            missing = [h for h, v in result["security_headers"].items()
                      if not v["present"]]
            if missing:
                result["flags"].append(
                    f"Missing security headers: {', '.join(missing)}"
                )

            # Flag interesting status codes
            if response.status_code == 200:
                result["flags"].append("Live host")
            elif response.status_code in [401, 403]:
                result["flags"].append("Protected resource")

            # Check interesting paths
            result["interesting_paths"] = check_interesting_paths(
                result["url"], session
            )

            # Flag critical findings
            critical = [p for p in result["interesting_paths"]
                       if p.get("severity") == "CRITICAL"]
            if critical:
                result["flags"].append(
                    f"CRITICAL: Sensitive paths exposed: "
                    f"{[p['path'] for p in critical]}"
                )

            return result

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except Exception:
            continue

    return None


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(targets, output_dir="results"):
    """
    Probe a list of hosts or a single domain.
    targets can be:
      - a single domain string: "example.com"
      - a list of subdomains from dns_module output
      - a path to a dns_module JSON results file
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — HTTP PROBER MODULE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Normalize targets input
    if isinstance(targets, str):
        if os.path.exists(targets):
            # It's a JSON file from dns_module
            with open(targets, "r") as f:
                dns_results = json.load(f)
            host_list = [s["subdomain"] for s in
                        dns_results.get("subdomains", [])]
            host_list.append(dns_results["target"])
        else:
            host_list = [targets]
    elif isinstance(targets, list):
        host_list = targets
    else:
        host_list = [str(targets)]

    print(f"\n[*] Probing {len(host_list)} hosts...")

    # Shared session for connection pooling
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; Nitakusaka/1.0)"
    })

    results     = []
    live_hosts  = []

    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        futures = {
            executor.submit(probe_host, host, session): host
            for host in host_list
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                live_hosts.append(result)
                techs = ", ".join(result["technologies"]) or "unknown"
                print(f"    [+] {result['status_code']} "
                      f"{result['url']:<50} "
                      f"[{techs}]")
                if result["title"]:
                    print(f"         Title : {result['title']}")
                for flag in result["flags"]:
                    if "CRITICAL" in flag:
                        print(f"         ⚠ {flag}")

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"http_{timestamp}.json")

    final_results = {
        "timestamp":   datetime.now().isoformat(),
        "total_hosts": len(host_list),
        "live_hosts":  len(live_hosts),
        "results":     results,
    }

    with open(output_path, "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"\n[*] {len(live_hosts)}/{len(host_list)} hosts alive")
    print(f"[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    return final_results

# ──────────────────────────────────────────────
#  HTTPX INTEGRATION
# ──────────────────────────────────────────────

import subprocess

HTTPX_PATH = r"C:\Program Files\httpx\httpx.exe"

def run_httpx(targets, output_dir="results"):
    """
    Run ProjectDiscovery httpx against targets.
    Faster and more feature-rich than our Python prober.
    Falls back to Python prober if httpx not found.
    targets: list of hosts or path to a file with hosts
    """
    if not os.path.exists(HTTPX_PATH):
        print("[!] httpx not found — falling back to Python prober")
        return None

    print(f"\n[*] Running httpx against targets...")

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"httpx_{timestamp}.json")

    # Write targets to temp file if list provided
    if isinstance(targets, list):
        targets_file = os.path.join(output_dir, "httpx_targets.txt")
        with open(targets_file, "w") as f:
            for target in targets:
                f.write(target + "\n")
        input_arg = ["-l", targets_file]
    elif isinstance(targets, str) and os.path.exists(targets):
        input_arg = ["-l", targets]
    else:
        input_arg = ["-u", targets]

    cmd = [
        HTTPX_PATH,
        *input_arg,
        "-title",           # extract page titles
        "-tech-detect",     # detect technologies
        "-status-code",     # show status codes
        "-content-length",  # show response size
        "-web-server",      # detect web server
        "-ip",              # resolve and show IP
        "-cname",           # show CNAME records
        "-tls-probe",       # probe TLS
        "-follow-redirects",# follow redirects
        "-json",            # JSON output for parsing
        "-o", output_path,  # save to file
        "-silent",          # no banner
        "-threads", "50",   # concurrent threads
    ]

    print(f"    [*] Command: {' '.join(cmd)}")

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse JSON output
        return parse_httpx_output(output_path)

    except subprocess.TimeoutExpired:
        print("[!] httpx timed out")
        return None
    except Exception as e:
        print(f"[!] httpx failed: {e}")
        return None


def parse_httpx_output(output_path):
    """
    Parse httpx JSON output into our standard format.
    httpx outputs one JSON object per line (JSONL format).
    """
    if not os.path.exists(output_path):
        print(f"[!] httpx output not found at {output_path}")
        return None

    results  = []
    critical = []

    try:
        with open(output_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)

                    result = {
                        "url":            data.get("url", ""),
                        "status_code":    data.get("status_code", None),
                        "title":          data.get("title", None),
                        "technologies":   data.get("technologies", []),
                        "web_server":     data.get("webserver", None),
                        "ip":             data.get("host", None),
                        "cname":          data.get("cname", []),
                        "content_length": data.get("content_length", None),
                        "tls":            data.get("tls", None),
                        "flags":          [],
                    }

                    # Flag interesting status codes
                    if result["status_code"] == 200:
                        result["flags"].append("Live host")
                    elif result["status_code"] in [401, 403]:
                        result["flags"].append("Protected resource")

                    results.append(result)

                    techs = ", ".join(result["technologies"]) or "unknown"
                    print(f"    [+] {result['status_code']} "
                          f"{result['url']:<50} [{techs}]")
                    if result["title"]:
                        print(f"         Title : {result['title']}")

                except json.JSONDecodeError:
                    continue

        print(f"\n[*] httpx found {len(results)} live hosts")

        return {
            "timestamp": datetime.now().isoformat(),
            "scanner":   "httpx",
            "results":   results,
            "critical":  critical,
        }

    except Exception as e:
        print(f"[!] Could not parse httpx output: {e}")
        return None