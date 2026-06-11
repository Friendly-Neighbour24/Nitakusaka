import socket
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

DEFAULT_THREADS  = 100
SOCKET_TIMEOUT   = 2
DEFAULT_PORT_RANGE = (1, 1024)

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888, 6379, 27017, 5432,
    1433, 2375, 9200, 9300, 11211, 6380, 5000,
    5001, 8000, 8001, 8008, 8888, 9000, 9001
]

SERVICE_MAP = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1723:  "PPTP",
    2375:  "Docker",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    6380:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

RISKY_PORTS = {
    23:    "Telnet transmits credentials in plaintext",
    2375:  "Docker API exposed — full container takeover possible",
    6379:  "Redis often runs with no authentication",
    9200:  "Elasticsearch often exposed with no authentication",
    11211: "Memcached amplification DDoS risk",
    27017: "MongoDB often exposed with no authentication",
    3389:  "RDP exposed — brute force and BlueKeep risk",
    5900:  "VNC exposed — brute force risk",
    445:   "SMB exposed — EternalBlue/ransomware risk",
}

# ──────────────────────────────────────────────
#  BANNER GRABBER
# ──────────────────────────────────────────────

def grab_banner(ip, port):
    """
    After confirming a port is open, try to read what
    the service sends back — this reveals software name
    and version which we can match against known CVEs.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))

        # Send a generic HTTP request for web ports
        # Other services send banners automatically on connect
        if port in [80, 8080, 8000, 8001, 8008, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner automatically
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner if banner else None

    except Exception:
        return None


# ──────────────────────────────────────────────
#  SINGLE PORT SCANNER
# ──────────────────────────────────────────────

def scan_port(ip, port):
    """
    Attempt a TCP connection to a single port.
    Returns result dict if open, None if closed.
    This function runs inside a thread.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            # Port is open — grab banner and check risk
            service = SERVICE_MAP.get(port, "unknown")
            banner  = grab_banner(ip, port)
            risk    = RISKY_PORTS.get(port, None)

            return {
                "port":    port,
                "service": service,
                "banner":  banner,
                "risk":    risk,
                "status":  "open"
            }
        return None

    except Exception:
        return None
    
    # ──────────────────────────────────────────────
#  MAIN SCANNER ENGINE
# ──────────────────────────────────────────────

def scan_target(ip, ports, threads=DEFAULT_THREADS):
    """
    Scan a list of ports concurrently using a thread pool.
    Returns all open ports with banners and risk flags.
    """
    open_ports = []
    total      = len(ports)
    completed  = 0

    print(f"\n[*] Scanning {total} ports on {ip} with {threads} threads...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in ports
        }

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result:
                open_ports.append(result)
                risk_flag = " ⚠ RISKY" if result["risk"] else ""
                print(f"    [+] {result['port']:5d}/tcp  {result['service']:<20}"
                      f"{risk_flag}")
                if result["banner"]:
                    banner_preview = result["banner"][:80].replace("\n", " ")
                    print(f"         Banner: {banner_preview}")
                if result["risk"]:
                    print(f"         Risk  : {result['risk']}")

            if completed % 100 == 0:
                print(f"    [*] Progress: {completed}/{total} "
                      f"({len(open_ports)} open so far)")

    open_ports.sort(key=lambda x: x["port"])
    print(f"\n[*] Scan complete. {len(open_ports)} open ports found.")
    return open_ports


# ──────────────────────────────────────────────
#  RESOLVE HOSTNAME TO IP
# ──────────────────────────────────────────────

def resolve_target(target):
    """
    Resolve a domain name to an IP address.
    Port scanning requires an IP, not a domain name.
    """
    try:
        ip = socket.gethostbyname(target)
        print(f"\n[*] Resolved {target} → {ip}")
        return ip
    except socket.gaierror as e:
        print(f"[!] Could not resolve {target}: {e}")
        return None


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(target, mode="top", port_range=DEFAULT_PORT_RANGE,
        output_dir="results"):
    """
    Full port scanning pipeline:
      mode='top'   — scan TOP_PORTS list (fast, covers most risks)
      mode='range' — scan a port range (thorough)
      mode='full'  — scan all 65535 ports (slow but complete)
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — PORT SCANNER MODULE")
    print(f"  Target : {target}")
    print(f"  Mode   : {mode}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Resolve domain to IP
    ip = resolve_target(target)
    if not ip:
        return None

    # Build port list based on mode
    if mode == "top":
        ports = TOP_PORTS
    elif mode == "range":
        ports = list(range(port_range[0], port_range[1] + 1))
    elif mode == "full":
        ports = list(range(1, 65536))
    else:
        ports = TOP_PORTS

    # Run the scan
    open_ports = scan_target(ip, ports)

    # Build results
    results = {
        "target":     target,
        "ip":         ip,
        "timestamp":  datetime.now().isoformat(),
        "mode":       mode,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "risky_ports": [p for p in open_ports if p["risk"]],
    }

    # Save to JSON
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace(".", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir,
                               f"ports_{safe_target}_{timestamp}.json")

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[*] Results saved to {output_path}")
    print(f"{'='*60}\n")

    return results
# ──────────────────────────────────────────────
#  NMAP INTEGRATION
# ──────────────────────────────────────────────

import subprocess
import xml.etree.ElementTree as ET

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"

NMAP_SCAN_TYPES = {
    "default":  "-sV -sC",
    "stealth":  "-sS -sV",
    "udp":      "-sU -sV",
    "xmas":     "-sX",
    "fin":      "-sF",
    "null":     "-sN",
    "full":     "-sV -sC -sS -O",
    "quick":    "-T4 -F",
    "os":       "-O",
}

def run_nmap(target, scan_type="default", ports=None):
    """
    Run Nmap against target and parse XML output.
    Falls back to pure Python scanner if Nmap not found.
    scan_type options: default, stealth, udp, xmas,
                       fin, null, full, quick, os
    """
    if not os.path.exists(NMAP_PATH):
        print("[!] Nmap not found — falling back to Python scanner")
        return None

    print(f"\n[*] Running Nmap {scan_type} scan against {target}...")

    # Build nmap command
    flags = NMAP_SCAN_TYPES.get(scan_type, "-sV")
    port_arg = f"-p {ports}" if ports else "-p-" if scan_type == "full" else ""
    output_file = f"results/nmap_{target.replace('.','_')}.xml"

    os.makedirs("results", exist_ok=True)

    cmd = [
        NMAP_PATH,
        flags,
        port_arg,
        "-oX", output_file,  # XML output for parsing
        "--open",            # only show open ports
        target
    ]

    # Remove empty strings from command
    cmd = [c for c in cmd if c]

    # Split flags string into list
    cmd_final = [NMAP_PATH]
    cmd_final.extend(flags.split())
    if port_arg:
        cmd_final.extend(port_arg.split())
    cmd_final.extend(["-oX", output_file, "--open", target])

    print(f"    [*] Command: {' '.join(cmd_final)}")

    try:
        process = subprocess.run(
            cmd_final,
            capture_output=True,
            text=True,
            timeout=300
        )

        if process.returncode != 0:
            print(f"[!] Nmap error: {process.stderr}")
            return None

        # Parse XML output
        return parse_nmap_xml(output_file, target)

    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out")
        return None
    except Exception as e:
        print(f"[!] Nmap failed: {e}")
        return None


def parse_nmap_xml(xml_file, target):
    """
    Parse Nmap XML output into our standard results format.
    This lets us feed Nmap results into our report module
    the same way as our Python scanner results.
    """
    if not os.path.exists(xml_file):
        print(f"[!] Nmap XML output not found at {xml_file}")
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        open_ports  = []
        risky_ports = []

        for host in root.findall("host"):
            # Get IP
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")

            # Get OS detection if available
            os_match = None
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_match = {
                    "name":     osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                }

            # Get open ports
            ports_elem = host.find("ports")
            if ports_elem:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        portid  = int(port.get("portid"))
                        service = port.find("service")

                        service_name    = service.get("name", "unknown") if service else "unknown"
                        service_product = service.get("product", "") if service else ""
                        service_version = service.get("version", "") if service else ""

                        # Collect NSE script results
                        scripts = {}
                        for script in port.findall("script"):
                            scripts[script.get("id")] = script.get("output")

                        risk = RISKY_PORTS.get(portid, None)

                        port_result = {
                            "port":            portid,
                            "service":         service_name,
                            "product":         service_product,
                            "version":         service_version,
                            "scripts":         scripts,
                            "risk":            risk,
                            "status":          "open"
                        }

                        open_ports.append(port_result)

                        if risk:
                            risky_ports.append(port_result)
                            print(f"    [+] {portid:5d}/tcp  {service_name:<15} "
                                  f"{service_product} {service_version} ⚠ RISKY")
                        else:
                            print(f"    [+] {portid:5d}/tcp  {service_name:<15} "
                                  f"{service_product} {service_version}")

                        if scripts:
                            for script_id, output in scripts.items():
                                preview = output[:100].replace("\n", " ") if output else ""
                                print(f"         [{script_id}]: {preview}")

        print(f"\n[*] Nmap found {len(open_ports)} open ports "
              f"({len(risky_ports)} risky)")

        return {
            "target":      target,
            "timestamp":   datetime.now().isoformat(),
            "scanner":     "nmap",
            "scan_type":   "nmap",
            "open_ports":  open_ports,
            "risky_ports": risky_ports,
            "os_match":    os_match if 'os_match' in locals() else None,
        }

    except ET.ParseError as e:
        print(f"[!] Could not parse Nmap XML: {e}")
        return None