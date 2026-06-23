#!/usr/bin/env python3
"""
Nitakusaka — Automated Offensive Reconnaissance Framework
Author: Hans (@Friendly-Neighbour24)
"""

import argparse
import sys
import os
from datetime import datetime

from modules import dns_module
from modules import port_module
from modules import http_module
from modules import correlator
from modules import report_module
from modules import reverse_dns
from modules import content_module
from modules import monitor

# Optional modules — import safely
try:
    from modules import ai_wordlist
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

try:
    from modules import vuln_module
    VULN_AVAILABLE = True
except ImportError:
    VULN_AVAILABLE = False


BANNER = r"""
    _   _ _ _        _                    _         
   | \ | (_) |      | |                  | |        
   |  \| |_| |_ __ _| | ___   _ ___  __ _| | ____ _ 
   | . ` | | __/ _` | |/ / | | / __|/ _` | |/ / _` |
   | |\  | | || (_| |   <| |_| \__ \ (_| |   < (_| |
   |_| \_|_|\__\__,_|_|\_\\__,_|___/\__,_|_|\_\__,_|

   Automated Offensive Reconnaissance Framework
   github.com/Friendly-Neighbour24/Nitakusaka
"""

# ──────────────────────────────────────────────
#  ARGUMENT PARSER
# ──────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="nitakusaka",
        description="Automated offensive reconnaissance framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python nitakusaka.py --target example.com --full
  python nitakusaka.py --target example.com --module dns
  python nitakusaka.py --target example.com --module ports --scan-type full
  python nitakusaka.py --target example.com --full --ai-wordlist
  python nitakusaka.py --target example.com --module vuln --templates owasp
        """
    )

    # Target
    parser.add_argument(
        "-t", "--target",
        help="target domain (e.g. example.com)",
    )
    parser.add_argument(
        "-r", "--reverse",
        help="reverse DNS scan an IP, CIDR block, or range "
             "(e.g. 196.216.10.0/24)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="continuously monitor target for changes",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="seconds between scans in watch mode (default: 3600)",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="run a single monitoring check against the last snapshot",
    )
    
    # Module selection
    parser.add_argument(
        "-m", "--module",
        choices=["dns", "ports", "http", "vuln","content", "correlate", "report"],
        help="run a single module only",
    )

    # Full scan
    parser.add_argument(
        "--full",
        action="store_true",
        help="run the complete recon pipeline",
    )

    # DNS options
    parser.add_argument(
        "--wordlist",
        help="custom wordlist path for DNS brute force",
    )
    parser.add_argument(
        "--ai-wordlist",
        action="store_true",
        help="generate AI contextual wordlist (requires API key)",
    )

    # Port options
    parser.add_argument(
        "--scan-type",
        choices=["top", "range", "full"],
        default="top",
        help="port scan mode (default: top)",
    )
    parser.add_argument(
        "--use-nmap",
        action="store_true",
        help="use Nmap engine instead of Python scanner",
    )

    # Vuln options
    parser.add_argument(
        "--templates",
        choices=["owasp", "cves", "misconfig", "exposed",
                 "takeover", "full"],
        default="owasp",
        help="nuclei template set (default: owasp)",
    )
    parser.add_argument(
        "--no-amass",
        action="store_true",
        help="skip Amass enumeration in vuln scan",
    )

    # Output options
    parser.add_argument(
        "--output",
        default="results",
        help="output directory (default: results)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="number of threads (default: 100)",
    )
    parser.add_argument(
        "--report-format",
        choices=["html", "markdown", "json", "all"],
        default="all",
        help="report format (default: all)",
    )

    return parser

# ──────────────────────────────────────────────
#  PIPELINE ORCHESTRATOR
# ──────────────────────────────────────────────

def run_full_pipeline(args):
    """
    Run the complete recon pipeline in sequence:
    DNS → Ports → HTTP → Vuln → Correlate → Report
    Each module's output feeds into the next.
    """
    target = args.target
    results = {}

    print(f"\n[*] Starting full recon pipeline against {target}")
    print(f"[*] This may take several minutes depending on options\n")

    # 1. Determine wordlist
    wordlist = args.wordlist
    if args.ai_wordlist and AI_AVAILABLE:
        print("[*] Generating AI contextual wordlist...")
        wordlist = ai_wordlist.run(target)

    # 2. DNS enumeration
    print("\n[+] PHASE 1/5 — DNS Enumeration")
    dns_results = dns_module.run(
        target,
        wordlist=wordlist if wordlist else dns_module.DEFAULT_WORDLIST,
        threads=args.threads,
        output_dir=args.output,
    )
    results["dns"] = dns_results

    # 3. Port scanning
    print("\n[+] PHASE 2/5 — Port Scanning")
    if args.use_nmap:
        port_results = port_module.run_nmap(target, scan_type="default")
    else:
        port_results = port_module.run(
            target, mode=args.scan_type, output_dir=args.output
        )
    results["ports"] = port_results

    # 4. HTTP probing — build target list from DNS results
    print("\n[+] PHASE 3/5 — HTTP Probing")
    http_targets = [target]
    if dns_results and dns_results.get("subdomains"):
        http_targets.extend(
            [s["subdomain"] for s in dns_results["subdomains"]]
        )
    http_results = http_module.run(http_targets, output_dir=args.output)
    results["http"] = http_results
    # Content discovery
    print("\n[+] PHASE 3.5/5 — Content Discovery")
    content_module.run(target, output_dir=args.output)


    # 5. Vulnerability scanning
    if VULN_AVAILABLE:
        print("\n[+] PHASE 4/5 — Vulnerability Scanning")
        vuln_results = vuln_module.run(
            target,
            template_set=args.templates,
            run_amass=not args.no_amass,
            output_dir=args.output,
        )
        results["vuln"] = vuln_results
    else:
        print("\n[!] PHASE 4/5 — Vuln module unavailable, skipping")

    # 6. Correlation
    print("\n[+] PHASE 5/5 — Correlating Findings")
    correlator.run(
        dns_results=dns_results,
        port_results=port_results,
        http_results=http_results,
        output_dir=args.output,
    )

    # 7. Report generation
    print("\n[+] Generating Reports")
    formats = (["html", "markdown", "json"]
               if args.report_format == "all"
               else [args.report_format])
    report_module.run(formats=formats, output_dir=args.output)

    print(f"\n[*] Full pipeline complete for {target}")
    print(f"[*] All results saved to {args.output}/")


def run_single_module(args):
    """
    Run just one module based on --module flag.
    """
    target = args.target

    if args.module == "dns":
        wordlist = args.wordlist
        if args.ai_wordlist and AI_AVAILABLE:
            wordlist = ai_wordlist.run(target)
        dns_module.run(
            target,
            wordlist=wordlist if wordlist else dns_module.DEFAULT_WORDLIST,
            threads=args.threads,
            output_dir=args.output,
        )

    elif args.module == "ports":
        if args.use_nmap:
            port_module.run_nmap(target, scan_type="default")
        else:
            port_module.run(
                target, mode=args.scan_type, output_dir=args.output
            )

    elif args.module == "http":
        http_module.run(target, output_dir=args.output)

    elif args.module == "content":
        content_module.run(target, output_dir=args.output)    

    elif args.module == "vuln":
        if VULN_AVAILABLE:
            vuln_module.run(
                target,
                template_set=args.templates,
                run_amass=not args.no_amass,
                output_dir=args.output,
            )
        else:
            print("[!] Vuln module unavailable. "
                  "Check Nuclei and Amass are installed.")

    elif args.module == "correlate":
        correlator.run(output_dir=args.output)

    elif args.module == "report":
        formats = (["html", "markdown", "json"]
                   if args.report_format == "all"
                   else [args.report_format])
        report_module.run(formats=formats, output_dir=args.output)

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def main():
    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

   # Monitoring runs standalone too
    if args.monitor or args.watch:
        if not args.target:
            print("[!] Monitoring requires --target")
            sys.exit(1)
        os.makedirs(args.output, exist_ok=True)
        monitor.run(
            args.target,
            watch=args.watch,
            interval=args.interval,
            threads=args.threads,
            output_dir=args.output,
        )
        sys.exit(0)

        # Reverse DNS runs standalone — handle it first
    if args.reverse:
        os.makedirs(args.output, exist_ok=True)
        reverse_dns.run(args.reverse, threads=args.threads,
                        output_dir=args.output)
        sys.exit(0)

    # Monitoring runs standalone too
    if args.monitor or args.watch:
        if not args.target:
            print("[!] Monitoring requires --target")
            sys.exit(1)
        os.makedirs(args.output, exist_ok=True)
        monitor.run(
            args.target,
            watch=args.watch,
            interval=args.interval,
            threads=args.threads,
            output_dir=args.output,
        )
        sys.exit(0)

    # Validate: need a target unless just correlating/reporting
    if not args.target and args.module not in ["correlate", "report"]:
        parser.print_help()
        print("\n[!] Error: --target or --reverse is required")
        sys.exit(1)

    # Show what's available
    if args.ai_wordlist and not AI_AVAILABLE:
        print("[!] AI wordlist requested but anthropic library "
              "not installed. Run: pip install anthropic")
    if args.module == "vuln" and not VULN_AVAILABLE:
        print("[!] Vuln module requested but unavailable.")

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    start_time = datetime.now()

    try:
        if args.full:
            run_full_pipeline(args)
        elif args.module:
            run_single_module(args)
        else:
            parser.print_help()
            print("\n[!] Specify either --full or --module")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        sys.exit(1)

    elapsed = datetime.now() - start_time
    print(f"\n[*] Total time: {elapsed}")


if __name__ == "__main__":
    main()
