"""
Self-Test Traffic Generator
=============================
Generates traffic patterns AGAINST YOUR OWN LOCALHOST (127.0.0.1) so you can
safely trigger and verify the live IDS's detection rules without touching
any other device or network.

IMPORTANT: Only ever point this at 127.0.0.1 (your own machine) or a test
device you own. Never run scans/floods against networks or systems that
are not yours - that is illegal in most countries even if "just testing".

Run live_ids.py in one terminal FIRST, then run this script in a second
terminal while it's capturing.

Usage:
    python self_test.py --test portscan
    python self_test.py --test pingflood
    python self_test.py --test all
"""

import argparse
import socket
import subprocess
import sys
import time


def run_port_scan_test(target="127.0.0.1", ports=range(20, 80)):
    print(f"[*] Simulating a port scan against {target} ({len(list(ports))} ports)...")
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect_ex((target, port))
        except Exception:
            pass
        finally:
            s.close()
    print("[*] Port scan simulation complete.")


def run_ping_flood_test(target="127.0.0.1", count=50):
    print(f"[*] Simulating a ping flood against {target} ({count} pings)...")
    is_windows = sys.platform.startswith("win")
    for _ in range(count):
        if is_windows:
            subprocess.run(["ping", "-n", "1", "-w", "200", target],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ping", "-c", "1", "-W", "1", target],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Ping flood simulation complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Self-test traffic generator for the Live IDS project")
    parser.add_argument("--test", choices=["portscan", "pingflood", "all"], default="all")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP - keep this as your own machine")
    args = parser.parse_args()

    if args.target not in ("127.0.0.1", "localhost"):
        confirm = input(f"WARNING: target is '{args.target}', not localhost. "
                         f"Only run this against systems you own. Type YES to continue: ")
        if confirm != "YES":
            print("Aborted.")
            sys.exit(0)

    if args.test in ("portscan", "all"):
        run_port_scan_test(args.target)
        time.sleep(1)
    if args.test in ("pingflood", "all"):
        run_ping_flood_test(args.target)
