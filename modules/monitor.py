import json
import os
import time
from datetime import datetime

from modules import dns_module
from modules import port_module

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

SNAPSHOT_DIR    = "snapshots"
DEFAULT_INTERVAL = 3600  # seconds between scans in watch mode (1 hour)

# ──────────────────────────────────────────────
#  SNAPSHOT MANAGEMENT
# ──────────────────────────────────────────────

def take_snapshot(target, threads=100):
    """
    Run a lightweight scan and capture the current state
    of the target as a snapshot — subdomains, open ports,
    and the technologies seen.
    """
    print(f"\n[*] Taking snapshot of {target}...")

    snapshot = {
        "target":     target,
        "timestamp":  datetime.now().isoformat(),
        "subdomains": [],
        "open_ports": [],
    }

    # DNS — capture live subdomains
    dns_results = dns_module.run(target, threads=threads,
                                 output_dir=SNAPSHOT_DIR)
    if dns_results:
        snapshot["subdomains"] = sorted([
            s["subdomain"] for s in dns_results.get("subdomains", [])
        ])

    # Ports — capture open ports
    port_results = port_module.run(target, mode="top",
                                   output_dir=SNAPSHOT_DIR)
    if port_results:
        snapshot["open_ports"] = sorted([
            p["port"] for p in port_results.get("open_ports", [])
        ])

    return snapshot


def save_snapshot(snapshot, target):
    """
    Save a snapshot as the latest baseline for this target.
    """
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    safe_target = target.replace(".", "_")
    path = os.path.join(SNAPSHOT_DIR, f"snapshot_{safe_target}.json")

    with open(path, "w") as f:
        json.dump(snapshot, f, indent=4)

    return path


def load_previous_snapshot(target):
    """
    Load the most recent saved snapshot for this target.
    Returns None if this is the first ever scan.
    """
    safe_target = target.replace(".", "_")
    path = os.path.join(SNAPSHOT_DIR, f"snapshot_{safe_target}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None

# ──────────────────────────────────────────────
#  DIFF ENGINE
# ──────────────────────────────────────────────

def compare_snapshots(old, new):
    """
    Compare two snapshots and return what changed.
    Detects new and removed subdomains, and new and
    closed ports.
    """
    changes = {
        "new_subdomains":     [],
        "removed_subdomains": [],
        "new_ports":          [],
        "closed_ports":       [],
        "has_changes":        False,
    }

    old_subs = set(old.get("subdomains", []))
    new_subs = set(new.get("subdomains", []))

    changes["new_subdomains"]     = sorted(new_subs - old_subs)
    changes["removed_subdomains"] = sorted(old_subs - new_subs)

    old_ports = set(old.get("open_ports", []))
    new_ports = set(new.get("open_ports", []))

    changes["new_ports"]    = sorted(new_ports - old_ports)
    changes["closed_ports"] = sorted(old_ports - new_ports)

    # Flag if anything changed at all
    if (changes["new_subdomains"] or changes["removed_subdomains"]
            or changes["new_ports"] or changes["closed_ports"]):
        changes["has_changes"] = True

    return changes


def print_changes(changes, target):
    """
    Print a clean summary of what changed since last scan.
    """
    if not changes["has_changes"]:
        print(f"\n[*] No changes detected for {target}")
        return

    print(f"\n{'='*60}")
    print(f"  ⚠ CHANGES DETECTED — {target}")
    print(f"{'='*60}")

    if changes["new_subdomains"]:
        print(f"\n  [+] NEW SUBDOMAINS ({len(changes['new_subdomains'])}):")
        for sub in changes["new_subdomains"]:
            print(f"      + {sub}")

    if changes["removed_subdomains"]:
        print(f"\n  [-] REMOVED SUBDOMAINS "
              f"({len(changes['removed_subdomains'])}):")
        for sub in changes["removed_subdomains"]:
            print(f"      - {sub}")

    if changes["new_ports"]:
        print(f"\n  [+] NEW OPEN PORTS ({len(changes['new_ports'])}):")
        for port in changes["new_ports"]:
            print(f"      + {port}")

    if changes["closed_ports"]:
        print(f"\n  [-] CLOSED PORTS ({len(changes['closed_ports'])}):")
        for port in changes["closed_ports"]:
            print(f"      - {port}")

    print(f"\n{'='*60}")


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(target, watch=False, interval=DEFAULT_INTERVAL,
        threads=100, output_dir="results"):
    """
    Monitor a target for changes.
      watch=False : single comparison against last snapshot
      watch=True  : loop forever, scanning every `interval` seconds
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — MONITORING MODULE")
    print(f"  Target  : {target}")
    print(f"  Mode    : {'continuous watch' if watch else 'single check'}")
    if watch:
        print(f"  Interval: {interval} seconds")
    print(f"{'='*60}")

    def single_check():
        # Load previous baseline
        previous = load_previous_snapshot(target)

        # Take new snapshot
        current = take_snapshot(target, threads)

        if previous is None:
            print(f"\n[*] First scan — establishing baseline.")
            print(f"    Subdomains: {len(current['subdomains'])}")
            print(f"    Open ports: {len(current['open_ports'])}")
            save_snapshot(current, target)
            return None

        # Compare
        changes = compare_snapshots(previous, current)
        print_changes(changes, target)

        # Save change report if anything changed
        if changes["has_changes"]:
            os.makedirs(output_dir, exist_ok=True)
            safe_target = target.replace(".", "_")
            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(
                output_dir, f"changes_{safe_target}_{timestamp}.json"
            )
            with open(report_path, "w") as f:
                json.dump({
                    "target":    target,
                    "timestamp": datetime.now().isoformat(),
                    "changes":   changes,
                }, f, indent=4)
            print(f"\n[*] Change report saved to {report_path}")
            try:
                from modules import report_module
                report_module.generate_change_report(changes, target, output_dir)
            except Exception as e:
                print("[!] Could not generate HTML change report:", e)

        # Update baseline
        save_snapshot(current, target)
        return changes

    if not watch:
        single_check()
    else:
        print(f"\n[*] Starting continuous monitoring. Press Ctrl+C to stop.")
        try:
            while True:
                single_check()
                print(f"\n[*] Next scan in {interval} seconds...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n\n[*] Monitoring stopped by user.")

    print(f"{'='*60}\n")
    