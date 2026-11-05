#!/usr/bin/env python3
"""Port Scanner Lite.

A small, careful TCP connect scanner for checking your own systems:
which ports are open, and what banner the service sends. It is
deliberately simple and rate-limited compared to full scanners like
Nmap. It exists for learning, lab work, and quick authorised checks.

Features:
- Top-ports scan or an explicit port list or range
- Concurrent connections with a bounded worker pool
- Optional banner grabbing with a short timeout
- JSON output for scripting

Only scan hosts you own or are explicitly authorised to test.
Unauthorised scanning can violate law and acceptable-use policies.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# Port number to common service name, for the default top-ports scan.
TOP_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb", 6379: "redis",
}

RISKY_SERVICES = {
    23: "Telnet sends credentials in cleartext. Replace it with SSH.",
    21: "Plain FTP sends credentials in cleartext. Prefer SFTP.",
    6379: "Redis is often deployed without authentication. Never expose it to untrusted networks.",
    27017: "MongoDB has a long history of open, unauthenticated deployments. Check authentication and bind address.",
    3389: "RDP is heavily targeted. Put it behind a VPN and enable NLA.",
    5900: "VNC is heavily targeted. Tunnel it over SSH or a VPN.",
    445: "SMB exposure is a common ransomware entry point (EternalBlue class bugs). Restrict it.",
}


@dataclass
class PortResult:
    port: int
    service: str
    banner: str | None = None
    note: str | None = None


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443', '1-1024', or a mix of both into a sorted list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid range {part}: start is after end")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"Ports out of range 1-65535: {sorted(invalid)}")
    return sorted(ports)


def check_port(host: str, port: int, timeout: float = 1.5, grab_banner: bool = True) -> PortResult | None:
    """Return a PortResult when the port accepts a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = None
            if grab_banner:
                sock.settimeout(1.0)
                try:
                    # Some services speak first (SSH, FTP, SMTP). For the
                    # rest, a tiny probe nudges a response out of HTTP-like
                    # services without sending anything harmful.
                    try:
                        data = sock.recv(128)
                    except socket.timeout:
                        data = b""
                    if not data:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = sock.recv(128)
                    banner = data.decode("utf-8", errors="replace").strip().splitlines()[0][:100] if data else None
                except (socket.timeout, OSError):
                    banner = None
            return PortResult(
                port=port,
                service=TOP_PORTS.get(port, "unknown"),
                banner=banner,
                note=RISKY_SERVICES.get(port),
            )
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan(host: str, ports: list[int], workers: int = 50, timeout: float = 1.5, grab_banner: bool = True) -> list[PortResult]:
    open_ports: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_port, host, p, timeout, grab_banner): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports, key=lambda r: r.port)


def resolve(host: str) -> str:
    return socket.gethostbyname(host)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Port Scanner Lite: a careful TCP connect scanner for authorised checks.")
    parser.add_argument("host", help="Hostname or IP you own or are authorised to test")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ports", help="Ports to scan, e.g. '22,80,443' or '1-1024'")
    group.add_argument("--top", action="store_true", help="Scan the built-in top ports list (default)")
    parser.add_argument("--workers", type=int, default=50, help="Max concurrent connections (default 50)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Per-connection timeout in seconds")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports) if args.ports else sorted(TOP_PORTS)
        ip = resolve(args.host)
    except (ValueError, socket.gaierror) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(f"Scanning {args.host} ({ip}), {len(ports)} ports...", file=sys.stderr)
    results = scan(ip, ports, workers=max(1, min(args.workers, 200)),
                   timeout=args.timeout, grab_banner=not args.no_banner)

    if args.json:
        print(json.dumps({"host": args.host, "ip": ip,
                          "open_ports": [vars(r) for r in results]}, indent=2))
    else:
        if not results:
            print("No open ports found in the scanned range.")
        for r in results:
            line = f"OPEN  {r.port:>5}/tcp  {r.service}"
            if r.banner:
                line += f"  banner: {r.banner}"
            print(line)
            if r.note:
                print(f"      Note: {r.note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
