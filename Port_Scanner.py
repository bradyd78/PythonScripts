import argparse
import errno
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORT_SERVICES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP server",
    68: "DHCP client",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB/CIFS",
    465: "SMTPS",
    514: "Syslog",
    548: "AFP",
    587: "SMTP (submission)",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS proxy",
    1433: "MSSQL",
    1434: "MSSQL monitor",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP proxy / alternative HTTP",
    8443: "HTTPS alternative",
}


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target '{target}': {exc}") from exc


def get_service_description(port, protocol="tcp"):
    if port in COMMON_PORT_SERVICES:
        return COMMON_PORT_SERVICES[port]

    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown or unassigned service"


def scan_port_tcp(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return port, "open" if result == 0 else "closed"


def scan_port_udp(ip, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(b"", (ip, port))
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                return port, "closed"
            return port, "unknown"

        try:
            sock.recvfrom(1024)
            return port, "open"
        except socket.timeout:
            return port, "open|filtered"
        except OSError as exc:
            if exc.errno in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH}:
                return port, "closed"
            return port, "unknown"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Scan TCP and UDP ports on a target host and save results in a structured JSON file."
    )
    parser.add_argument(
        "target",
        help="Target hostname or IPv4 address to scan.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout in seconds for each probe (default: 0.5).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=200,
        help="Number of parallel scanner threads (default: 200).",
    )
    parser.add_argument(
        "--start-port",
        type=int,
        default=1,
        help="First port to scan (default: 1).",
    )
    parser.add_argument(
        "--end-port",
        type=int,
        default=65535,
        help="Last port to scan (default: 65535).",
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "all"],
        default="all",
        help="Which protocol(s) to scan (default: all).",
    )
    parser.add_argument(
        "--output",
        default="scan_results.json",
        help="Path to save structured JSON results (default: scan_results.json).",
    )
    return parser.parse_args()


def scan_ports(ip, ports, scan_fn, timeout, workers):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(scan_fn, ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            try:
                port, status = future.result()
            except Exception:
                continue
            results.append({"port": port, "status": status})
    return sorted(results, key=lambda item: item["port"])


def write_results(path, data):
    with open(path, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=2)


def summarize_results(results, protocol):
    lines = []
    if not results:
        return [f"No {protocol.upper()} scan results."], 0

    count = 0
    for result in results:
        if protocol == "tcp" and result["status"] == "open":
            count += 1
            lines.append(f"  {result['port']:5d} - {get_service_description(result['port'], protocol)}")
        elif protocol == "udp" and result["status"] in {"open", "open|filtered"}:
            count += 1
            lines.append(
                f"  {result['port']:5d} - {result['status']} - {get_service_description(result['port'], protocol)}"
            )

    if not lines:
        return [f"No open or filtered {protocol.upper()} ports found."], 0

    header = [f"\n{protocol.upper()} results:"]
    return header + lines, count


def main():
    args = parse_arguments()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        raise SystemExit("Port range must be between 1 and 65535 and start-port must be <= end-port.")

    ip = resolve_target(args.target)
    protocols = [args.protocol] if args.protocol != "all" else ["tcp", "udp"]
    print(f"Resolving target '{args.target}'... {ip}")
    print(
        f"Scanning {args.start_port}-{args.end_port} on {args.target} ({ip}) for {', '.join(protocols).upper()} with {args.workers} threads..."
    )

    ports = range(args.start_port, args.end_port + 1)
    results = {"target": args.target, "ip": ip, "range": {"start_port": args.start_port, "end_port": args.end_port}, "protocols": protocols, "timeout": args.timeout, "workers": args.workers, "results": {}}

    if "tcp" in protocols:
        tcp_results = scan_ports(ip, ports, scan_port_tcp, args.timeout, args.workers)
        results["results"]["tcp"] = [
            {
                "port": item["port"],
                "status": item["status"],
                "service": get_service_description(item["port"], "tcp"),
            }
            for item in tcp_results
        ]

    if "udp" in protocols:
        udp_results = scan_ports(ip, ports, scan_port_udp, args.timeout, args.workers)
        results["results"]["udp"] = [
            {
                "port": item["port"],
                "status": item["status"],
                "service": get_service_description(item["port"], "udp"),
            }
            for item in udp_results
        ]

    write_results(args.output, results)

    if "tcp" in protocols:
        tcp_lines, tcp_count = summarize_results(results["results"]["tcp"], "tcp")
        print("\n".join(tcp_lines))
        print(f"Found {tcp_count} open TCP port(s).")

    if "udp" in protocols:
        udp_lines, udp_count = summarize_results(results["results"]["udp"], "udp")
        print("\n".join(udp_lines))
        print(f"Found {udp_count} open or filtered UDP port(s).")

    print(f"\nSaved scan results to {args.output}")


if __name__ == "__main__":
    main()
