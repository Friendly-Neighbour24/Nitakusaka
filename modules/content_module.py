import subprocess
import json
import os
from datetime import datetime

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

FFUF_PATH = r"C:\Program Files\ffuf\ffuf.exe"
DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__),
                                "../wordlists/directories.txt")

# Status codes worth reporting
INTERESTING_CODES = [200, 201, 204, 301, 302, 307, 401, 403, 405, 500]

# Severity hints for discovered paths
SENSITIVE_PATHS = {
    ".git":        "CRITICAL",
    ".env":        "CRITICAL",
    "backup":      "HIGH",
    "admin":       "HIGH",
    "config":      "HIGH",
    "phpmyadmin":  "HIGH",
    "wp-admin":    "MEDIUM",
    "test":        "MEDIUM",
    "dev":         "MEDIUM",
    "api":         "INFO",
    "login":       "INFO",
}

# ──────────────────────────────────────────────
#  FFUF RUNNER
# ──────────────────────────────────────────────

def run_ffuf(target, wordlist=DEFAULT_WORDLIST, output_dir="results"):
    """
    Run ffuf directory/file discovery against a target URL.
    Returns parsed results or None if ffuf is unavailable.
    """
    if not os.path.exists(FFUF_PATH):
        print("[!] ffuf not found — skipping content discovery")
        return None

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found at {wordlist}")
        return None

    # Normalize target into a fuzzable URL
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    fuzz_url = target.rstrip("/") + "/FUZZ"

    print(f"\n[*] Running ffuf content discovery on {target}...")
    print(f"    [*] Fuzzing: {fuzz_url}")

    os.makedirs(output_dir, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "")
    safe_target = safe_target.replace(".", "_").replace("/", "_")
    output_path = os.path.join(
        output_dir, f"ffuf_{safe_target}_{timestamp}.json"
    )

    # Build the status code filter string
    codes = ",".join(str(c) for c in INTERESTING_CODES)

    cmd = [
        FFUF_PATH,
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", codes,          # match these status codes
        "-o", output_path,     # output file
        "-of", "json",         # output format JSON
        "-t", "40",            # 40 concurrent threads
        "-rate", "100",        # max 100 requests/sec
        "-timeout", "10",      # 10s timeout per request
        "-s",                  # silent mode
    ]

    print(f"    [*] Wordlist: {os.path.basename(wordlist)}")
    print(f"    [*] Rate limit: 100 req/s")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return parse_ffuf_output(output_path, target)
    except subprocess.TimeoutExpired:
        print("[!] ffuf timed out — parsing partial results")
        return parse_ffuf_output(output_path, target)
    except Exception as e:
        print(f"[!] ffuf failed: {e}")
        return None
    
    # ──────────────────────────────────────────────
#  OUTPUT PARSER
# ──────────────────────────────────────────────

def classify_path(path):
    """
    Assign a severity to a discovered path based on
    sensitive keywords. Returns severity string or None.
    """
    path_lower = path.lower()
    for keyword, severity in SENSITIVE_PATHS.items():
        if keyword in path_lower:
            return severity
    return None


def parse_ffuf_output(output_path, target):
    """
    Parse ffuf JSON output into our standard format.
    ffuf outputs a single JSON object with a 'results' array.
    """
    if not os.path.exists(output_path):
        print(f"[!] ffuf output not found at {output_path}")
        return None

    try:
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Could not parse ffuf output: {e}")
        return None

    discovered = []
    raw_results = data.get("results", [])

    for item in raw_results:
        url      = item.get("url", "")
        status   = item.get("status", 0)
        length   = item.get("length", 0)
        path     = url.split("/FUZZ")[0]
        word     = item.get("input", {}).get("FUZZ", "")
        full_url = f"{target.rstrip('/')}/{word}"

        severity = classify_path(word)

        entry = {
            "url":         full_url,
            "path":        word,
            "status_code": status,
            "size":        length,
            "severity":    severity,
        }
        discovered.append(entry)

        flag = f" [{severity}]" if severity else ""
        print(f"    [+] {status}  {full_url}{flag}")

    # Sort: sensitive findings first, then by status code
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                     "INFO": 3, None: 4}
    discovered.sort(key=lambda x: (severity_rank.get(x["severity"], 4),
                                   x["status_code"]))

    print(f"\n[*] ffuf discovered {len(discovered)} paths")
    return {
        "target":     target,
        "timestamp":  datetime.now().isoformat(),
        "scanner":    "ffuf",
        "discovered": discovered,
        "total":      len(discovered),
    }


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(target, wordlist=DEFAULT_WORDLIST, output_dir="results"):
    """
    Run content discovery against a target and save results.
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — CONTENT DISCOVERY MODULE")
    print(f"  Target : {target}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    results = run_ffuf(target, wordlist, output_dir)

    if results is None:
        print("[!] Content discovery did not complete.")
        return None

    # Save normalized results
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace("https://", "").replace("http://", "")
    safe_target = safe_target.replace(".", "_").replace("/", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"content_{safe_target}_{timestamp}.json"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    # Quick summary
    sensitive = [d for d in results["discovered"] if d["severity"]]
    if sensitive:
        print(f"\n[*] {len(sensitive)} sensitive path(s) flagged:")
        for s in sensitive:
            print(f"    [{s['severity']}] {s['url']}")

    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    return results
