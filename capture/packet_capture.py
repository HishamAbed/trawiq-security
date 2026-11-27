
import argparse
import csv
from collections import Counter
from pathlib import Path

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    rdpcap,
    sniff,
    conf,
    get_if_list,
    PcapWriter,
)
from scapy.arch.windows import get_windows_if_list


# =========================================================
# 1. PACKET ANALYSIS
# =========================================================

def analyze_packet(packet):
    info = {
        "source_ip": None,
        "destination_ip": None,
        "protocol": "Other",
        "source_port": None,
        "destination_port": None,
        "packet_size": len(packet),
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


# =========================================================
# 2. PCAP FILE READING
# =========================================================

def read_pcap(file_path):
    if not Path(file_path).is_file():
        print(f"PCAP file not found: {file_path}")
        return

    packets = rdpcap(file_path)

    print(f"\nTotal Packets: {len(packets)}")
    print("-" * 60)

    for index, packet in enumerate(packets, start=1):
        result = analyze_packet(packet)

        print(f"\nPacket #{index}")
        for key, value in result.items():
            print(f"{key}: {value}")


# =========================================================
# 3. TRAFFIC STATISTICS
# =========================================================

def analyze_traffic_statistics(file_path):
    if not Path(file_path).is_file():
        print(f"PCAP file not found: {file_path}")
        return

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


# =========================================================
# 4. EXPORT PCAP FEATURES TO CSV
# =========================================================

def export_to_csv(file_path, output_path):
    if not Path(file_path).is_file():
        print(f"PCAP file not found: {file_path}")
        return

    packets = rdpcap(file_path)

    if not packets:
        print("No packets found!")
        return

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = [analyze_packet(packet) for packet in packets]

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = list(rows[0].keys())

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV exported successfully: {output_path}")
    print(f"Total records: {len(rows)}")


# =========================================================
# 5. AUTOMATIC NETWORK INTERFACE DETECTION
# =========================================================

def resolve_capture_interface(requested_interface=None):
    available_interfaces = get_if_list()
    adapters = get_windows_if_list()

    def find_npf_interface(adapter):
        guid = str(adapter.get("guid", "")).strip("{}").lower()

        if not guid:
            return None

        for interface in available_interfaces:
            if guid in interface.lower():
                return interface

        return None

    # Manual interface selection, if requested.
    if requested_interface:
        for interface in available_interfaces:
            if interface.lower() == requested_interface.lower():
                return interface

        for adapter in adapters:
            if adapter.get("name", "").lower() == requested_interface.lower():
                interface = find_npf_interface(adapter)

                if interface:
                    return interface

        raise RuntimeError(
            f"Could not find network interface: {requested_interface}"
        )

    # First choice: interface used by the default route.
    try:
        route_info = conf.route.route("0.0.0.0")
        source_ip = route_info[2]

        for adapter in adapters:
            if source_ip in adapter.get("ips", []):
                interface = find_npf_interface(adapter)

                if interface:
                    print(
                        f"Default route interface detected: "
                        f"{adapter.get('name')}"
                    )
                    return interface

    except Exception as error:
        print(f"Default route detection failed: {error}")

    # Fallback: find an active physical adapter with IPv4.
    excluded_keywords = [
        "loopback",
        "vmware",
        "virtualbox",
        "hyper-v",
        "wan miniport",
        "npcap",
        "bluetooth",
        "wi-fi direct",
        "wintun",
        "tap-windows",
    ]

    candidates = []

    for adapter in adapters:
        name = adapter.get("name", "")
        description = adapter.get("description", "")

        adapter_text = f"{name} {description}".lower()
        ips = adapter.get("ips", [])

        has_ipv4 = any(
            "." in ip and not ip.startswith("127.")
            for ip in ips
        )

        is_virtual = any(
            keyword in adapter_text
            for keyword in excluded_keywords
        )

        if has_ipv4 and not is_virtual:
            interface = find_npf_interface(adapter)

            if interface:
                candidates.append((adapter, interface))

    if not candidates:
        raise RuntimeError(
            "No suitable active network interface was found."
        )

    # Prefer Wi-Fi when no default-route match is available.
    for adapter, interface in candidates:
        name = adapter.get("name", "").lower()
        if "wi-fi" in name or "wifi" in name or "wireless" in name:
            return interface

    return candidates[0][1]


# =========================================================
# 6. LIVE PACKET CAPTURE
# =========================================================

def capture_live(
    duration=30,
    requested_interface=None,
    csv_output="data/processed/live_traffic.csv",
    pcap_output="data/processed/live_capture.pcap",
):
    if duration <= 0:
        raise ValueError("Capture duration must be greater than zero.")

    interface = resolve_capture_interface(requested_interface)

    csv_path = Path(csv_output)
    pcap_path = Path(pcap_output)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_size",
    ]

    protocol_counter = Counter()
    packet_count = 0

    print("\n===== TRAWIQ LIVE CAPTURE =====")
    print(f"Selected interface: {interface}")
    print(f"Capture duration: {duration} seconds")
    print("Starting packet capture...")
    print("Generate normal network traffic to test the capture.\n")

    pcap_writer = PcapWriter(
        str(pcap_path),
        append=False,
        sync=True,
    )

    try:
        with open(
            csv_path,
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            csv_writer = csv.DictWriter(
                csvfile,
                fieldnames=fieldnames
            )
            csv_writer.writeheader()

            def process_packet(packet):
                nonlocal packet_count

                features = analyze_packet(packet)

                csv_writer.writerow(features)
                pcap_writer.write(packet)

                packet_count += 1
                protocol_counter[features["protocol"]] += 1

                if packet_count <= 5:
                    print(f"Packet #{packet_count}: {packet.summary()}")

            sniff(
                iface=interface,
                prn=process_packet,
                store=False,
                timeout=duration,
            )

    finally:
        pcap_writer.close()

    print("\n===== LIVE CAPTURE RESULTS =====")
    print(f"Total Packets Captured: {packet_count}")

    for protocol, count in protocol_counter.items():
        print(f"{protocol}: {count}")

    print(f"\nPCAP saved to: {pcap_path}")
    print(f"CSV saved to: {csv_path}")


# =========================================================
# 7. PROGRAM ENTRY POINT
# =========================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TRAWIQ Security - Network Packet Capture"
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Start live network packet capture",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Live capture duration in seconds",
    )

    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Optional network interface name",
    )

    parser.add_argument(
        "--pcap",
        type=str,
        default="data/raw/sample.pcap",
        help="PCAP file to analyze",
    )

    args = parser.parse_args()

    try:
        if args.live:
            capture_live(
                duration=args.duration,
                requested_interface=args.interface,
            )

        else:
            file_path = args.pcap

            if not Path(file_path).is_file():
                print(f"PCAP file not found: {file_path}")
                print("Generate a sample first:")
                print("python capture/generate_sample.py")
            else:
                read_pcap(file_path)
                analyze_traffic_statistics(file_path)

                export_to_csv(
                    file_path,
                    "data/processed/network_traffic.csv",
                )

                print("\nTRAWIQ Security Analysis Completed!")

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")

    except Exception as error:
        print(f"\nError: {error}")
