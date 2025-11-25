#!/usr/bin/env python3
"""
Network Diagnostics Toolkit
- Ping
- Traceroute
- DNS lookup
- Basic TCP port scan (22, 80, 443)
"""

import subprocess
import socket
import sys
import platform
import shutil
from typing import List, Tuple


COMMON_PORTS = [22, 80, 443]
PING_COUNT = 4
CONNECT_TIMEOUT = 2.0


def run_command(cmd: List[str]) -> Tuple[int, str]:
    """Run a shell command and return (returncode, output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()
    except Exception as e:
        return 1, f"Error running command {' '.join(cmd)}: {e}"


def ping_host(target: str) -> Tuple[bool, str]:
    """Ping target and return (reachable, raw_output)."""
    os_name = platform.system().lower()
    if os_name.startswith("win"):
        cmd = ["ping", "-n", str(PING_COUNT), target]
    else:
        cmd = ["ping", "-c", str(PING_COUNT), target]

    code, out = run_command(cmd)
    reachable = (code == 0)
    return reachable, out


def traceroute_host(target: str) -> Tuple[bool, str]:
    """Run traceroute/tracert and return (success, raw_output)."""
    os_name = platform.system().lower()
    if os_name.startswith("win"):
        tracer_cmd = shutil.which("tracert") or "tracert"
        cmd = [tracer_cmd, target]
    else:
        tracer_cmd = shutil.which("traceroute") or "traceroute"
        cmd = [tracer_cmd, target]

    code, out = run_command(cmd)
    success = (code == 0)
    return success, out


def dns_lookup(target: str) -> Tuple[bool, str, List[str]]:
    """Resolve DNS for target. Return (success, primary_ip, aliases)."""
    try:
        host, aliaslist, ipaddrlist = socket.gethostbyname_ex(target)
        primary_ip = ipaddrlist[0] if ipaddrlist else "N/A"
        return True, primary_ip, ipaddrlist
    except Exception as e:
        return False, "N/A", [str(e)]


def scan_ports(target: str, ports: List[int]) -> List[Tuple[int, str]]:
    """
    Try TCP connect on each port.
    Return list of (port, status) where status is 'open', 'closed', or 'timeout/error'.
    """
    results = []
    for port in ports:
        status = "closed"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CONNECT_TIMEOUT)
                result = s.connect_ex((target, port))
                if result == 0:
                    status = "open"
                else:
                    status = "closed"
        except socket.timeout:
            status = "timeout"
        except Exception as e:
            status = f"error ({e})"
        results.append((port, status))
    return results


def summarize_ping(output: str) -> str:
    """Try to pull a simple summary line out of ping output."""
    lines = output.splitlines()
    summary_line = ""
    for line in lines[::-1]:
        if "loss" in line.lower() or "Packets:" in line or "statistics" in line:
            summary_line = line.strip()
            break
    return summary_line or "See raw output."


def print_section(title: str):
    print()
    print("=" * (len(title) + 4))
    print(f"  {title}")
    print("=" * (len(title) + 4))


def main():
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    else:
        target = input("Enter hostname or IP to diagnose: ").strip()

    if not target:
        print("No target provided. Exiting.")
        sys.exit(1)

    print_section("NETWORK DIAGNOSTICS")
    print(f"Target: {target}")

    # DNS first so we get IP for later
    print_section("DNS LOOKUP")
    dns_ok, primary_ip, details = dns_lookup(target)
    if dns_ok:
        print(f"Primary IP: {primary_ip}")
        print(f"All resolved IPs: {', '.join(details)}")
    else:
        print("DNS resolution failed.")
        print("Details:", ", ".join(details))

    # Ping
    print_section("PING TEST")
    ping_ok, ping_out = ping_host(target)
    print("Reachable:" if ping_ok else "Ping failed.")
    print(summarize_ping(ping_out))
    print("\n--- Raw ping output ---")
    print(ping_out)

    # Traceroute
    print_section("TRACEROUTE")
    trace_ok, trace_out = traceroute_host(target)
    if trace_ok:
        print("Traceroute completed (see below).")
    else:
        print("Traceroute failed or partially completed (see below).")
    print(trace_out)

    # Port scan
    print_section("PORT SCAN")
    ports_result = scan_ports(primary_ip if dns_ok else target, COMMON_PORTS)
    for port, status in ports_result:
        print(f"Port {port}: {status}")

    print_section("SUMMARY")
    print(f"DNS OK:        {dns_ok}")
    print(f"Ping OK:       {ping_ok}")
    print("Ports:")
    for port, status in ports_result:
        print(f"  {port:<5} -> {status}")


if __name__ == "__main__":
    main()