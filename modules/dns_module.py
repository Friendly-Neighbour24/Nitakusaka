import dns.resolver
import dns.zone 
import dns.query
import dns.exception
import json
import os 
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

#___________________________________
# CONFIGURATION
#____________________________________

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "../wordlists/subdomains.txt")
DEFAULT_THREADS = 100
DNS_TIMEOUT = 2 
RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']

#___________________________________
# ZONE TRANSFER ATTEMPT
#___________________________________

def attempt_zone_transfer(domain):
    """Attempt a DNS zone transfer (AXFR) against all nameservers.
    Most servers block this — but misconfigured ones hand over
    every DNS record they have. Always try this first."""

    print(f"\n[*] Attempting zone transfer for {domain}...")
    findings = []

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns) for ns in ns_records]

        for ns in nameservers:
            print(f"    [*] Trying nameserver: {ns}")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns.rstrip("."), domain, timeout=5)
                )
                print(f"    [!] ZONE TRANSFER SUCCEEDED on {ns} — vulnerability found!")
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

#___________________________________
# SINGLE SUBDOMAIN RESOLVER
#___________________________________

def resolve_subdomain(subdomain):
    """  Try to resolve a single subdomain to an A record.
    Returns a result dict if alive, None if it doesn't exist.
    This function runs inside a thread."""

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    try:
        answers = resolver.resolve(subdomain, 'A')
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

# ──────────────────────────────────────────────
#  ROOT DOMAIN RECORD ENUMERATION
# ──────────────────────────────────────────────

def enumerate_root_records(domain):
    """
    Pull all interesting DNS records from the root domain.
    MX records reveal mail providers.
    TXT records reveal SPF/DKIM config and third-party services.
    NS records reveal the hosting provider.
    """
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

# ──────────────────────────────────────────────
#  SUBDOMAIN BRUTE FORCE
# ──────────────────────────────────────────────

def bruteforce_subdomains(domain, wordlist_path=DEFAULT_WORDLIST,
                          threads=DEFAULT_THREADS):
    """
    Load a wordlist, build candidate subdomains, resolve them
    concurrently using a thread pool, collect live results.
    """
    # Load wordlist
    if not os.path.exists(wordlist_path):
        print(f"[!] Wordlist not found at {wordlist_path}")
        return []

    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    candidates = [f"{word}.{domain}" for word in words]
    total      = len(candidates)
    found      = []

    print(f"\n[*] Brute forcing {total} subdomains with {threads} threads...")

    # Thread pool — runs resolve_subdomain() on each candidate concurrently
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
                print(f"    [+] FOUND: {result['subdomain']} → {result['ips']}")

            # Progress indicator every 100 checks
            if completed % 100 == 0:
                print(f"    [*] Progress: {completed}/{total} "
                      f"({len(found)} found so far)")

    print(f"\n[*] Brute force complete. {len(found)} live subdomains found.")
    return found

# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(domain, wordlist=DEFAULT_WORDLIST, threads=DEFAULT_THREADS,
        output_dir="results"):
    """
    Orchestrates the full DNS enumeration:
      1. Zone transfer attempt
      2. Root record enumeration
      3. Subdomain brute force
      4. Save results to JSON
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — DNS MODULE")
    print(f"  Target : {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    results = {
        "target":        domain,
        "timestamp":     datetime.now().isoformat(),
        "zone_transfer": [],
        "root_records":  {},
        "subdomains":    [],
    }

    # 1. Zone transfer
    results["zone_transfer"] = attempt_zone_transfer(domain)

    # 2. Root DNS records
    results["root_records"] = enumerate_root_records(domain)

    # 3. Subdomain brute force
    results["subdomains"] = bruteforce_subdomains(domain, wordlist, threads)

    # 4. Save to JSON
    os.makedirs(output_dir, exist_ok=True)
    safe_domain  = domain.replace(".", "_")
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path  = os.path.join(output_dir,
                                f"dns_{safe_domain}_{timestamp}.json")

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    return results