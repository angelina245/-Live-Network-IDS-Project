"""
Live Network Intrusion Detection System (IDS)
================================================
Captures live network traffic on your machine and detects common attack
patterns in real time:
  1. Port Scans       - one source IP hitting many different ports quickly
  2. Ping Floods       - excessive ICMP (ping) traffic from one source
  3. SYN Floods        - excessive half-open TCP connections (SYN without ACK)
  4. Traffic Spikes    - sudden bursts of packets, possible DoS indicator

IMPORTANT:
  - Must be run with Administrator privileges (Windows) or sudo (Linux/Mac).
  - Requires Npcap (Windows) or libpcap (Linux/Mac) and the 'scapy' library.
  - This only observes traffic on YOUR OWN machine/network. Do not run this
    against networks you do not own or have explicit permission to monitor.

Usage:
    python live_ids.py                  (auto-picks default interface)
    python live_ids.py --iface "Wi-Fi"  (specify a network interface)
    python live_ids.py --duration 120   (run for 120 seconds then stop)
"""

import argparse
import time
import datetime
import csv
from collections import defaultdict, deque

from scapy.all import sniff, IP, TCP, ICMP, conf

# ---------------------------------------------------------------------------
# Detection thresholds (tune these based on your network)
# ---------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15        # distinct ports from one IP within window
PORT_SCAN_WINDOW = 5            # seconds
PING_FLOOD_THRESHOLD = 30       # ICMP packets from one IP within window
PING_FLOOD_WINDOW = 5           # seconds
SYN_FLOOD_THRESHOLD = 40        # SYN packets from one IP within window
SYN_FLOOD_WINDOW = 5            # seconds
TRAFFIC_SPIKE_THRESHOLD = 200   # total packets within window
TRAFFIC_SPIKE_WINDOW = 5        # seconds

# ---------------------------------------------------------------------------
# State tracking
# ---------------------------------------------------------------------------
port_hits = defaultdict(lambda: deque())       # src_ip -> deque[(time, port)]
icmp_hits = defaultdict(lambda: deque())        # src_ip -> deque[time]
syn_hits = defaultdict(lambda: deque())         # src_ip -> deque[time]
all_packet_times = deque()                      # deque[time]

alerts = []
packet_count = 0
start_time = None


def log_alert(category, severity, src_ip, detail):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    alert = {"time": ts, "category": category, "severity": severity, "src_ip": src_ip, "detail": detail}
    alerts.append(alert)
    print(f"[{ts}] [{severity}] {category} from {src_ip} - {detail}")


def prune(dq, window, now):
    while dq and now - dq[0] > window:
        dq.popleft()


def process_packet(pkt):
    global packet_count
    packet_count += 1
    now = time.time()

    all_packet_times.append(now)
    prune(all_packet_times, TRAFFIC_SPIKE_WINDOW, now)
    if len(all_packet_times) > TRAFFIC_SPIKE_THRESHOLD:
        log_alert("Traffic Spike", "MEDIUM", "multiple sources",
                   f"{len(all_packet_times)} packets in last {TRAFFIC_SPIKE_WINDOW}s (possible DoS)")
        all_packet_times.clear()

    if not pkt.haslayer(IP):
        return
    src_ip = pkt[IP].src

    # --- Port scan detection (TCP packets to many distinct ports) ---
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        dq = port_hits[src_ip]
        dq.append((now, dport))
        prune_ports(dq, now)
        distinct_ports = len({p for _, p in dq})
        if distinct_ports >= PORT_SCAN_THRESHOLD:
            log_alert("Port Scan", "HIGH", src_ip,
                       f"{distinct_ports} distinct ports probed in last {PORT_SCAN_WINDOW}s")
            dq.clear()

        # --- SYN flood detection ---
        flags = pkt[TCP].flags
        if flags == "S":  # SYN only, no ACK
            sdq = syn_hits[src_ip]
            sdq.append(now)
            prune(sdq, SYN_FLOOD_WINDOW, now)
            if len(sdq) >= SYN_FLOOD_THRESHOLD:
                log_alert("SYN Flood", "CRITICAL", src_ip,
                           f"{len(sdq)} SYN packets in last {SYN_FLOOD_WINDOW}s")
                sdq.clear()

    # --- Ping flood detection ---
    if pkt.haslayer(ICMP):
        idq = icmp_hits[src_ip]
        idq.append(now)
        prune(idq, PING_FLOOD_WINDOW, now)
        if len(idq) >= PING_FLOOD_THRESHOLD:
            log_alert("Ping Flood", "HIGH", src_ip,
                       f"{len(idq)} ICMP packets in last {PING_FLOOD_WINDOW}s")
            idq.clear()


def prune_ports(dq, now):
    while dq and now - dq[0][0] > PORT_SCAN_WINDOW:
        dq.popleft()


def write_results():
    with open("../results/alerts_log.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time", "category", "severity", "src_ip", "detail"])
        writer.writeheader()
        writer.writerows(alerts)

    with open("../results/session_summary.txt", "w") as f:
        f.write("LIVE NETWORK IDS - SESSION SUMMARY\n")
        f.write(f"Start time: {start_time}\n")
        f.write(f"End time: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Total packets observed: {packet_count}\n")
        f.write(f"Total alerts triggered: {len(alerts)}\n\n")
        by_cat = defaultdict(int)
        for a in alerts:
            by_cat[a["category"]] += 1
        for cat, count in by_cat.items():
            f.write(f"  {cat}: {count}\n")
    print(f"\nSession summary written to results/session_summary.txt")
    print(f"Full alert log written to results/alerts_log.csv")


def main():
    global start_time
    parser = argparse.ArgumentParser(description="Live Network IDS")
    parser.add_argument("--iface", default=None, help="Network interface name (e.g. 'Wi-Fi')")
    parser.add_argument("--duration", type=int, default=60, help="How many seconds to capture")
    args = parser.parse_args()

    start_time = datetime.datetime.now().isoformat(timespec="seconds")
    print(f"Available interfaces: {conf.ifaces if hasattr(conf, 'ifaces') else 'n/a'}")
    print(f"Starting live capture for {args.duration} seconds... (Ctrl+C to stop early)")
    print(f"Thresholds: PortScan>={PORT_SCAN_THRESHOLD} ports/{PORT_SCAN_WINDOW}s, "
          f"PingFlood>={PING_FLOOD_THRESHOLD}/{PING_FLOOD_WINDOW}s, "
          f"SYNFlood>={SYN_FLOOD_THRESHOLD}/{SYN_FLOOD_WINDOW}s\n")

    try:
        sniff(prn=process_packet, iface=args.iface, timeout=args.duration, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        write_results()
        print(f"\nDone. Captured {packet_count} packets, {len(alerts)} alerts triggered.")


if __name__ == "__main__":
    main()
