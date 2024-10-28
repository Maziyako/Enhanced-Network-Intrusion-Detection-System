# Enhanced Network Intrusion Detection System (IDS)

## Project Overview
This project is an Enhanced Network Intrusion Detection System (IDS) built using Python and Scapy. It monitors network traffic to detect potential threats, specifically focusing on detecting port scanning and SYN flood attacks. The IDS is designed to capture packets, analyze them, and alert for suspicious activities.

## Features
- **Packet Capture**: Continuously captures network packets for analysis.
- **Port Scanning Detection**: Identifies multiple connection attempts to different ports from the same IP within a short time, flagging potential reconnaissance attempts.
- **SYN Flood Detection**: Monitors for a high volume of SYN requests from a single IP, alerting for potential SYN flood attacks.
- **Debugging Output**: Prints diagnostic information to verify packet capture and detection processes.

## Prerequisites
- **Python 3.6+**
- **Scapy Library**: Used for packet capture and network traffic analysis.
- **Npcap**: Required on Windows to allow packet capture.

### Installing Scapy and Pandas
```bash
pip install scapy pandas
