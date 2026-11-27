import csv
from pathlib import Path
from scapy.all import IP, IPv6, TCP, UDP, ICMP, rdpcap


def analyze_packet(packet):

    info = {
        "source_ip": None,
        "destination_ip": None,
        "protocol": "Other",
        "source_port": None,
        "destination_port": None,
        "packet_size": len(packet)
    }

    if IP in packet:
        info["source_ip"] = packet[IP].src
        info["destination_ip"] = packet[IP].dst

    elif IPv6 in packet:
        info["source_ip"] = packet[IPv6].src
        info["destination_ip"] = packet[IPv6].dst

    if TCP in packet:
        info["protocol"] = "TCP"
        info["source_port"] = packet[TCP].sport
        info["destination_port"] = packet[TCP].dport

    elif UDP in packet:
        info["protocol"] = "UDP"
        info["source_port"] = packet[UDP].sport
        info["destination_port"] = packet[UDP].dport

    elif ICMP in packet:
        info["protocol"] = "ICMP"

    return info


def read_pcap(file_path):

    packets = rdpcap(file_path)

    print(f"\nTotal Packets: {len(packets)}")
    print("-" * 60)

    for index, packet in enumerate(packets, start=1):

        result = analyze_packet(packet)

        print(f"\nPacket #{index}")
        for key, value in result.items():
            print(f"{key}: {value}")
            
from collections import Counter


def analyze_traffic_statistics(file_path):

    packets = rdpcap(file_path)

    protocol_counter = Counter()

    for packet in packets:

        if TCP in packet:
            protocol_counter["TCP"] += 1

        elif UDP in packet:
            protocol_counter["UDP"] += 1

        elif ICMP in packet:
            protocol_counter["ICMP"] += 1

        else:
            protocol_counter["Other"] += 1

    print("\n===== TRAFFIC STATISTICS =====")
    print(f"Total Packets: {len(packets)}")

    for protocol, count in protocol_counter.items():
        print(f"{protocol}: {count}")

def export_to_csv(file_path, output_path):

    packets = rdpcap(file_path)

    rows = []

    for packet in packets:
        features = analyze_packet(packet)
        rows.append(features)

    if not rows:
        print("No packets found!")
        return

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="") as csvfile:

        fieldnames = rows[0].keys()

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV exported successfully: {output_path}")
    print(f"Total records: {len(rows)}")
    
if __name__ == "__main__":

    file_path = "data/raw/sample.pcap"

    # Step 1: Read and analyze packets
    read_pcap(file_path)

    # Step 2: Calculate traffic statistics
    analyze_traffic_statistics(file_path)

    # Step 3: Export packet features to CSV
    export_to_csv(
        file_path,
        "data/processed/network_traffic.csv"
    )

    print("\nTRAWIQ Security Analysis Completed!")