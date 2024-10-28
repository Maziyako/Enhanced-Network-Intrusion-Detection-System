from scapy.all import sniff
from collections import defaultdict

# Function to capture packets
def capture_packets(packet_count=200):
    packets = sniff(count=packet_count)
    print(f"Captured {len(packets)} packets")  # Debugging line
    return packets

# Function to detect port scanning
def detect_port_scan(packets, threshold=10):
    port_scan_attempts = defaultdict(set)
    
    for pkt in packets:
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            src_ip = pkt["IP"].src
            dst_port = pkt["TCP"].dport
            port_scan_attempts[src_ip].add(dst_port)
            print(f"Port attempt: {src_ip} -> Port {dst_port}")  # Debugging line
            
            # Check if the number of attempted ports exceeds the threshold
            if len(port_scan_attempts[src_ip]) > threshold:
                print(f"Port scanning detected from IP: {src_ip}")
                port_scan_attempts[src_ip].clear()  # Clear after detection to avoid repeated alerts

# Function to detect SYN flood attacks
def detect_syn_flood(packets, threshold=100):
    syn_counts = defaultdict(int)
    
    for pkt in packets:
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":  # "S" flag indicates SYN packet
            src_ip = pkt["IP"].src
            syn_counts[src_ip] += 1
            print(f"SYN attempt from IP: {src_ip}")  # Debugging line
            
            # Check if the SYN packet count exceeds the threshold
            if syn_counts[src_ip] > threshold:
                print(f"SYN Flood detected from IP: {src_ip}")
                syn_counts[src_ip] = 0  # Reset count after detection to avoid repeated alerts

# Main block to execute the IDS functions
if __name__ == "__main__":
    # Capture packets
    captured_packets = capture_packets()
    
    # Run detection functions on the captured packets
    detect_port_scan(captured_packets)
    detect_syn_flood(captured_packets)
