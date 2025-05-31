# ThreatTrace
ThreatTrace is a powerful Bash-based PCAP/PCAPNG analysis toolkit for offline inspection of network captures. It extracts and analyzes critical metadata, protocols, user agents, file transfers, suspicious service:filename patterns, and generates an investigation summary — all without needing to open Wireshark.

  > Perfect for: CTF challenges, malware analysis, traffic auditing, and offline forensic investigations.

# Features
-  Extract top IP addresses (source & destination)
-  Detect protocols used
-  Identify TCP/UDP ports
-  Parse HTTP User Agents & Requested Files
-  Detect FTP, SMB, and Email (SMTP/POP/IMAP) transfers
-  Trace SSH connections
-  Extract DNS Queries & Queried Domains
-  Locate potential service:file references
-  Analyze and summarize suspicious indicators

# Requirements
-  apt install tshark (linux)
-  brew install tshark (macos)

# Usage
1.  chmod +x pcap-analyzer.sh
2.  ./pcap-analyzer.sh

# Output Summary
The script will output findings in structured categories like:

- `Top IP addresses`
- `Protocols used`
- `Open TCP/UDP ports`
- `FTP/SMB transfers`
- `HTTP file downloads`
- `HTTP User Agents`
- `DNS Queries and Domain Names`
- `Service:File strings`
- `Suspicious Patterns and Summary`

# Sample Output
ThreatTrace Network Analyzer
File: suspicious-network.pcapng

Top 10 Source IPs:
1. 192.168.1.5 — 342 packets
2. 92.123.1.4  — 220 packets
...

HTTP User Agents:
- Mozilla/5.0 (Windows NT 10.0; Win64; x64)...

DNS Queries:
- suspiciousdomain.ru
- updater.microsoft.com

FTP Transfers:
- /incoming/malware.exe
...

🔍 Summary:
- Detected suspicious file: malware.exe from FTP
- Domain suspiciousdomain.ru resolved by internal host
- Potential exfiltration over SMB
...


