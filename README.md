# Live Network Intrusion Detection System (IDS)

A real-time network traffic analyzer that captures live packets on your own
machine and detects common attack patterns: port scans, ping floods, SYN
floods, and general traffic spikes.

## ⚠️ Important / Legal note

This tool only ever captures traffic that passes through **your own network
interface**. The included self-test script only ever targets `127.0.0.1`
(your own computer) by default. **Never run scanning or flood traffic
against any network or device you do not own or have explicit written
permission to test** - doing so is illegal in most countries, including
under India's IT Act, 2000.

## Folder structure

```
Network_IDS_Project/
├── sniffer/
│   ├── live_ids.py     # The live packet capture + detection engine
│   └── self_test.py    # Safely generates test traffic against localhost
├── results/
│   ├── alerts_log.csv       # Generated after each run - every alert raised
│   └── session_summary.txt  # Generated after each run - summary stats
└── report/
    └── (project report goes here)
```

## Setup (Windows)

1. Install **Npcap**: https://npcap.com/#download
   - During install, check "Install Npcap in WinPcap API-compatible Mode"
2. Install Python dependency:
   ```
   pip install scapy
   ```
3. Run VS Code / your terminal **as Administrator** (required for packet
   capture - right-click VS Code icon → "Run as administrator")

## How to run

**Terminal 1 - start the IDS (run as Administrator):**
```
cd sniffer
python live_ids.py --duration 90
```
This listens for 90 seconds and prints alerts live as they happen.

To find your interface name if needed, the script prints available
interfaces at startup. You can also pass it directly:
```
python live_ids.py --iface "Wi-Fi" --duration 90
```

**Terminal 2 - generate safe test traffic against yourself, while Terminal 1
is still capturing:**
```
cd sniffer
python self_test.py --test all
```

You should see Terminal 1 print alerts like:
```
[HIGH] Port Scan from 127.0.0.1 - 17 distinct ports probed in last 5s
[HIGH] Ping Flood from 127.0.0.1 - 32 ICMP packets in last 5s
```

After it finishes (or you press Ctrl+C), check:
- `results/alerts_log.csv` - every alert, in spreadsheet form
- `results/session_summary.txt` - a quick summary

## What it detects

| Detection      | How it works                                                   | Severity |
|----------------|-----------------------------------------------------------------|----------|
| Port Scan      | One source IP touching many distinct ports in a short window    | HIGH     |
| Ping Flood     | Excessive ICMP (ping) packets from one source in a short window | HIGH     |
| SYN Flood      | Excessive TCP SYN-only packets from one source (half-open conns)| CRITICAL |
| Traffic Spike  | Sudden burst of total packets across all sources                | MEDIUM   |

Thresholds are configurable at the top of `live_ids.py`.
