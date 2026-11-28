from pathlib import Path
from scapy.all import (
    ICMP,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    TCP,
    UDP,
    wrpcap,
)


def generate_sample_pcap(output_path="data/raw/sample.pcap"):
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    packets = [
        # IPv4 TCP packets with flag variations (SYN, SYN-ACK, ACK, FIN-ACK, RST)
        IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="SA"),
        IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="A"),
        IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=12345, dport=80, flags="FA"),
        IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="R"),
        # IPv4 UDP packet
        IP(src="192.168.1.15", dst="8.8.8.8") / UDP(sport=5000, dport=53),
        # IPv4 ICMP packet
        IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8, code=0),
        # IPv6 TCP packet
        IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(sport=54321, dport=443, flags="S"),
        # IPv6 UDP packet
        IPv6(src="2001:db8::10", dst="2001:db8::53") / UDP(sport=51000, dport=53),
        # IPv6 ICMPv6 packet
        IPv6(src="2001:db8::10", dst="2001:db8::1") / ICMPv6EchoRequest(),
    ]

    wrpcap(str(target), packets)
    print(f"Sample PCAP created successfully: {target}")
    print(f"Total packets: {len(packets)}")


if __name__ == "__main__":
    generate_sample_pcap()
