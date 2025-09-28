from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_handler(packet):
    # Check if the packet has an IP layer to filter for relevant packets
    if IP in packet:
        # Extract source and destination IP addresses and protocol
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Print the basic information
        print(f"IP Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")

        # Check for specific protocols to extract more details
        if TCP in packet:
            print(f"    TCP: Source Port {packet[TCP].sport} -> Destination Port {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP: Source Port {packet[UDP].sport} -> Destination Port {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    ICMP: Type {packet[ICMP].type}")

# Start the sniffer
print("Starting network sniffer... Press Ctrl+C to stop.")
# The sniff() function captures packets and passes them to our handler
sniff(prn=packet_handler, store=0)