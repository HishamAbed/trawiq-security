from scapy.all import IP, TCP, UDP, ICMP, wrpcap

packets = []

# TCP packet
packets.append(
    IP(src="192.168.1.10", dst="192.168.1.20") /
    TCP(sport=12345, dport=80)
)

# UDP packet
packets.append(
    IP(src="192.168.1.15", dst="8.8.8.8") /
    UDP(sport=5000, dport=53)
)

# ICMP packet
packets.append(
    IP(src="192.168.1.10", dst="8.8.8.8") /
    ICMP()
)

wrpcap("data/raw/sample.pcap", packets)

print("Sample PCAP created successfully!")
print(f"Total packets: {len(packets)}")