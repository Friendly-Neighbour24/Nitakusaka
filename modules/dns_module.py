# dns_module.py
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "../wordlists/subdomains.txt")
DEFAULT_THREADS = 100
DNS_TIMEOUT = 2
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

def attempt_zone_transfer(domain):
    print(f"\n[*] Attempting zone transfer for {domain}...")
    findings = []
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        nameservers = [str(ns) for ns in ns_records]
        for ns in nameservers:
            print(f"    [*] Trying nameserver: {ns}")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns.rstrip("."), domain, timeout=5)
                )
                print(f"    [!] ZONE TRANSFER SUCCEEDED on {ns}")
                for name, node in zone.nodes.items():
                    findings.append({
                        "name": str(name),
                        "records": str(node.to_text(name))
                    })
            except Exception:
                print(f"    [-] Zone transfer blocked on {ns}")
    except Exception as e:
        print(f"    [-] Could not retrieve nameservers: {e}")
    return findings

def resolve_subdomain(subdomain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(subdomain, "A")
        ip_list = [str(r) for r in answers]
        return {
            "subdomain": subdomain,
            "ips": ip_list,
            "status": "alive"
        }
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return {
            "subdomain": subdomain,
            "ips": [],
            "status": "no_a_record"
        }
    except dns.exception.Timeout:
        return None
    except Exception:
        return None

def enumerate_root_records(domain):
    print(f"\n[*] Enumerating DNS records for {domain}...")
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
            print(f"    [+] {record_type}: {records[record_type]}")
        except Exception:
            records[record_type] = []
    return records

def bruteforce_subdomains(domain, wordlist_path=DEFAULT_WORDLIST, threads=DEFAULT_THREADS):
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found at {wordlist_path}")
        return []
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    candidates = [f"{word}.{domain}" for word in words]
    total = len(candidates)
    found = []
    print(f"\n[*] Brute forcing {total} subdomains with {threads} threads...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, candidate): candidate
            for candidate in candidates
        }
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                found.append(result)
                print(f"    [+] FOUND: {result['subdomain']} -> {result['ips']}")
            if completed % 100 == 0:
                print(f"    [*] Progress: {completed}/{total} ({len(found)} found so far)")
    print(f"\n[*] Brute force complete. {len(found)} live subdomains found.")
    return found

def run(domain, wordlist=DEFAULT_WORDLIST, threads=DEFAULT_THREADS, output_dir="results"):
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA - DNS MODULE")
    print(f"  Target : {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    results = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "zone_transfer": [],
        "root_records": {},
        "subdomains": [],
    }
    results["zone_transfer"] = attempt_zone_transfer(domain)
    results["root_records"] = enumerate_root_records(domain)
    results["subdomains"] = bruteforce_subdomains(domain, wordlist, threads)
    os.makedirs(output_dir, exist_ok=True)
    safe_domain = domain.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"dns_{safe_domain}_{timestamp}.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")
    return results