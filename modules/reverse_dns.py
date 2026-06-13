import socket
import json
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

DEFAULT_THREADS = 100
SOCKET_TIMEOUT  = 2

# Maximum IPs to scan from a CIDR block as a safety limit
# /16 = 65536 IPs which is too many — we cap it
MAX_CIDR_HOSTS = 4096

# ──────────────────────────────────────────────
#  REVERSE DNS LOOKUP
# ──────────────────────────────────────────────

def reverse_lookup(ip):
    """
    Perform a reverse DNS (PTR) lookup on a single IP.
    Returns the hostname if one exists, None otherwise.
    This function runs inside a thread.
    """
    try:
        socket.setdefaulttimeout(SOCKET_TIMEOUT)
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {
            "ip":       ip,
            "hostname": hostname,
            "aliases":  aliases,
        }
    except (socket.herror, socket.gaierror):
        # No PTR record for this IP — completely normal
        return None
    except Exception:
        return None


# ──────────────────────────────────────────────
#  CIDR EXPANSION
# ──────────────────────────────────────────────

def expand_cidr(cidr):
    """
    Expand a CIDR block into individual IP addresses.
    Example: 196.216.10.0/24 → [196.216.10.0, ... 196.216.10.255]
    Respects the MAX_CIDR_HOSTS safety cap.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid CIDR block: {e}")
        return []

    hosts = list(network.hosts())

    if len(hosts) > MAX_CIDR_HOSTS:
        print(f"[!] CIDR block too large ({len(hosts)} hosts). "
              f"Capping at {MAX_CIDR_HOSTS}.")
        hosts = hosts[:MAX_CIDR_HOSTS]

    return [str(ip) for ip in hosts]


# ──────────────────────────────────────────────
#  PARSE TARGET INPUT
# ──────────────────────────────────────────────

def parse_target(target):
    """
    Figure out what kind of input we got and turn it into
    a list of IPs to scan.
    Accepts:
      - single IP:    196.216.10.5
      - CIDR block:   196.216.10.0/24
      - IP range:     196.216.10.1-196.216.10.50
    """
    target = target.strip()

    # CIDR block
    if "/" in target:
        print(f"[*] Expanding CIDR block {target}...")
        return expand_cidr(target)

    # IP range (start-end)
    if "-" in target:
        try:
            start_str, end_str = target.split("-")
            start = ipaddress.ip_address(start_str.strip())
            end   = ipaddress.ip_address(end_str.strip())
            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current += 1
                if len(ips) > MAX_CIDR_HOSTS:
                    print(f"[!] Range too large. Capping at "
                          f"{MAX_CIDR_HOSTS}.")
                    break
            return ips
        except Exception as e:
            print(f"[!] Invalid IP range: {e}")
            return []

    # Single IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        print(f"[!] Not a valid IP, CIDR, or range: {target}")
        return []
    
    # ──────────────────────────────────────────────
#  MAIN SCANNER
# ──────────────────────────────────────────────

def scan_range(ips, threads=DEFAULT_THREADS):
    """
    Run reverse DNS lookups across a list of IPs concurrently.
    Returns all IPs that resolved to a hostname.
    """
    found     = []
    total     = len(ips)
    completed = 0

    print(f"\n[*] Reverse scanning {total} IPs with {threads} threads...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(reverse_lookup, ip): ip
            for ip in ips
        }

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                found.append(result)
                print(f"    [+] {result['ip']:<16} → {result['hostname']}")

            if completed % 256 == 0:
                print(f"    [*] Progress: {completed}/{total} "
                      f"({len(found)} resolved)")

    print(f"\n[*] Reverse scan complete. "
          f"{len(found)} IPs resolved to hostnames.")
    return found


# ──────────────────────────────────────────────
#  GROUP BY DOMAIN
# ──────────────────────────────────────────────

def group_by_domain(results):
    """
    Group discovered hostnames by their root domain.
    Helps spot related infrastructure across the IP range.
    """
    domains = {}

    for result in results:
        hostname = result["hostname"]
        parts    = hostname.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
        else:
            root = hostname

        if root not in domains:
            domains[root] = []
        domains[root].append({
            "ip":       result["ip"],
            "hostname": hostname,
        })

    return domains


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(target, threads=DEFAULT_THREADS, output_dir="results"):
    """
    Full reverse DNS pipeline:
      1. Parse target (IP, CIDR, or range)
      2. Reverse lookup every IP concurrently
      3. Group results by root domain
      4. Save to JSON
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — REVERSE DNS MODULE")
    print(f"  Target : {target}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # 1. Parse target into IP list
    ips = parse_target(target)
    if not ips:
        print("[!] No valid IPs to scan.")
        return None

    # 2. Scan
    results = scan_range(ips, threads)

    # 3. Group by domain
    domains = group_by_domain(results)

    if domains:
        print(f"\n[*] Discovered {len(domains)} distinct root domains:")
        for root, hosts in domains.items():
            print(f"    [+] {root} ({len(hosts)} host(s))")

    # 4. Build and save results
    final_results = {
        "target":         target,
        "timestamp":      datetime.now().isoformat(),
        "ips_scanned":    len(ips),
        "ips_resolved":   len(results),
        "distinct_domains": len(domains),
        "hostnames":      results,
        "grouped_domains": domains,
    }

    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace(".", "_").replace("/", "_").replace("-", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(
        output_dir, f"reverse_{safe_target}_{timestamp}.json"
    )

    with open(output_path, "w") as f:
        json.dump(final_results, f, indent=4)

    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    # Generate HTML report from this reverse scan
    try:
        from modules import report_module
        report_data = report_module.build_report_data({"reverse": final_results})
        report_data["target"] = target
        report_module.generate_html_report(report_data, output_dir)
    except Exception as e:
        print("[!] Could not generate HTML report:", e)

    return final_results