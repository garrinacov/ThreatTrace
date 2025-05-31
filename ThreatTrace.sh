#!/bin/bash

clear

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                      🕷️ ThreatTrace v1.0                        "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

read -p "Enter the full path to your PCAP/PCAPNG file: " FILE

if [[ ! -f "$FILE" ]]; then
  echo "File not found!"
  exit 1
fi

echo
echo "File: $FILE"
date
echo

echo "[✓] tshark supports export objects."
echo

# Top Talkers (Source and Destination IPs)
echo "Top 10 IP addresses (source):"
tshark -r "$FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -10
echo
echo "Top 10 IP addresses (destination):"
tshark -r "$FILE" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -10
echo

# Protocols and Ports
echo "Detected Protocols and Services:"
tshark -r "$FILE" -T fields -e _ws.col.Protocol | sort | uniq -c | sort -nr
echo

echo "TCP/UDP Ports in Use:"
tshark -r "$FILE" -T fields -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport | \
grep -E '[0-9]' | tr '\t' '\n' | sort -n | uniq -c | sort -nr | head -20
echo

# FTP Transfers
echo "[✓] FTP Transfers:"
tshark -r "$FILE" -Y "ftp.request.command" -T fields -e ftp.request.command -e ftp.request.arg
echo

# SMB Transfers
echo "[✓] SMB Transfers:"
tshark -r "$FILE" -Y "smb" -T fields -e smb.cmd -e smb.filename | sort | uniq -c
echo

# HTTP User Agents
echo "[✓] HTTP User Agents:"
tshark -r "$FILE" -Y "http.user_agent" -T fields -e http.user_agent | sort | uniq -c | sort -nr
echo

# HTTP Files
echo "[✓] HTTP Files (GET/POST requests with filenames):"
tshark -r "$FILE" -Y "http.request" -T fields -e http.host -e http.request.uri | \
grep -E "\.(exe|zip|rar|pdf|docx?|xlsx?|js|php|html?|jar|bin|sh|bat|msi|dll)" | sort | uniq -c | sort -nr
echo

# Email Protocols
echo "[✓] Email Protocols Detected:"
echo "- SMTP:"
tshark -r "$FILE" -Y "smtp" -T fields -e smtp.req.parameter
echo "- POP:"
tshark -r "$FILE" -Y "pop" -T fields -e pop.request
echo "- IMAP:"
tshark -r "$FILE" -Y "imap" -T fields -e imap.request
echo

# SSH Connections
echo "[✓] SSH Connections (TCP port 22):"
tshark -r "$FILE" -Y "tcp.port==22" -T fields -e ip.src -e ip.dst | sort | uniq -c
echo

# DNS Queries
echo "[✓] DNS Queries:"
tshark -r "$FILE" -Y "dns.qry.name" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -20
echo

# Domain extraction (FQDNs seen)
echo "[✓] Domain Names Detected in Traffic:"
tshark -r "$FILE" -T fields -e http.host | grep -E "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort | uniq -c | sort -nr | head -20
echo

# File References in Packet Data
echo "[✓] Potential File References in Packets:"
tshark -r "$FILE" -x | grep -E -i '\.exe|\.zip|\.rar|\.tar|\.gz|\.pdf|\.docx?|\.xlsx?|\.js|\.php|\.html?|\.jar|\.dll' | sort | uniq
echo

# Service:File Strings
echo "[✓] Searching for Service:File Strings (in packet data):"
tshark -r "$FILE" -x | grep -E -i 'ftp:.*\.(exe|zip|rar|pdf|docx?|xlsx?|js|php|html?|jar|sh|bat)|http:.*\.(exe|zip|rar)' | sort | uniq
echo

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                       ANALYSIS SUMMARY                          "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Suspicious IPs (external IPs)
echo "[!] External IPs communicating frequently:"
tshark -r "$FILE" -T fields -e ip.src -e ip.dst | grep -Ev "^10\.|^192\.168|^172\.1[6-9]|^172\.2[0-9]|^172\.3[01]" | \
grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -nr | head -10
echo

# Suspicious Ports
echo "[!] Uncommon or suspicious ports detected:"
tshark -r "$FILE" -T fields -e tcp.dstport | grep -v -E '^80$|^443$|^22$|^25$|^110$|^143$' | sort | uniq -c | sort -nr | head -10
echo

# Suspicious Files
echo "[!] Potential malware or executable files transferred:"
tshark -r "$FILE" -Y "http.request" -T fields -e http.host -e http.request.uri | \
grep -E "\.exe|\.dll|\.jar|\.bat|\.sh" | sort | uniq -c | sort -nr
echo

# Suspicious Domains
echo "[!] High-volume or suspicious domains:"
tshark -r "$FILE" -Y "dns.qry.name" -T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -10
echo

echo "[✓] Done. Review the summary section for potentially malicious indicators."

