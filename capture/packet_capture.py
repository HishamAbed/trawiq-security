import argparse
import csv
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import (
    ICMP,
    IP,
    IPv6,
    PcapWriter,
    TCP,
    UDP,
    conf,
    get_if_addr,
    get_if_list,
    rdpcap,
    sniff,
)
from scapy.error import Scapy_Exception
from scapy.layers.inet6 import _ICMPv6

PACKET_FIELDS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "ip_version",
    "ttl",
    "protocol",
    "source_port",
    "destination_port",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "packet_size",
]


# =========================================================
# 1. PACKET ANALYSIS
# =========================================================

def _format_timestamp(raw_time):
    if raw_time is None:
        return None
    try:
        return datetime.fromtimestamp(
            float(raw_time), tz=timezone.utc
        ).isoformat(timespec="microseconds")
    except (TypeError, ValueError, OSError):
        return None


def analyze_packet(packet):
    info = {field: None for field in PACKET_FIELDS}
    info["timestamp"] = _format_timestamp(getattr(packet, "time", None))
    info["protocol"] = "Other"
    info["packet_size"] = len(packet)

    if IP in packet:
        info["source_ip"] = packet[IP].src
        info["destination_ip"] = packet[IP].dst
        info["ip_version"] = 4
        info["ttl"] = packet[IP].ttl
    elif IPv6 in packet:
        info["source_ip"] = packet[IPv6].src
        info["destination_ip"] = packet[IPv6].dst
        info["ip_version"] = 6
        info["ttl"] = packet[IPv6].hlim

    if TCP in packet:
        info["protocol"] = "TCP"
        info["source_port"] = packet[TCP].sport
        info["destination_port"] = packet[TCP].dport
        info["tcp_flags"] = str(packet[TCP].flags)
    elif UDP in packet:
        info["protocol"] = "UDP"
        info["source_port"] = packet[UDP].sport
        info["destination_port"] = packet[UDP].dport
    elif ICMP in packet:
        info["protocol"] = "ICMP"
        info["icmp_type"] = packet[ICMP].type
        info["icmp_code"] = packet[ICMP].code
    elif _ICMPv6 in packet:
        icmp6 = packet[_ICMPv6]
        info["protocol"] = "ICMPv6"
        info["icmp_type"] = getattr(icmp6, "type", None)
        info["icmp_code"] = getattr(icmp6, "code", None)

    return info


# =========================================================
# 2. PCAP FILE READING & HELPERS
# =========================================================

def _load_pcap(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    try:
        packets = rdpcap(str(path))
    except (Scapy_Exception, EOFError, OSError, ValueError) as error:
        raise RuntimeError(f"Failed to read PCAP file '{file_path}': {error}") from error

    return packets


def _ensure_unique_path(path):
    target = Path(path)
    if not target.exists():
        return target

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = target.with_name(f"{target.stem}_{timestamp}{target.suffix}")
    counter = 1
    while candidate.exists():
        candidate = target.with_name(
            f"{target.stem}_{timestamp}_{counter}{target.suffix}"
        )
        counter += 1
    return candidate


def read_pcap(file_path):
    try:
        packets = _load_pcap(file_path)
    except (FileNotFoundError, RuntimeError) as error:
        print(error)
        return

    if not packets:
        print(f"PCAP file is empty: {file_path}")
        return

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
    try:
        packets = _load_pcap(file_path)
    except (FileNotFoundError, RuntimeError) as error:
        print(error)
        return

    if not packets:
        print(f"PCAP file is empty: {file_path}")
        return

    protocol_counter = Counter(analyze_packet(pkt)["protocol"] for pkt in packets)

    print("\n===== TRAFFIC STATISTICS =====")
    print(f"Total Packets: {len(packets)}")
    for protocol, count in protocol_counter.items():
        print(f"{protocol}: {count}")


# =========================================================
# 4. EXPORT PCAP FEATURES TO CSV
# =========================================================

def export_to_csv(file_path, output_path):
    try:
        packets = _load_pcap(file_path)
    except (FileNotFoundError, RuntimeError) as error:
        print(error)
        return

    if not packets:
        print(f"No packets found in PCAP file: {file_path}")
        return

    target_path = Path(output_path)
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        rows = [analyze_packet(packet) for packet in packets]
        with open(target_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=PACKET_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    except OSError as error:
        raise RuntimeError(f"Failed to write CSV file '{target_path}': {error}") from error

    print(f"CSV exported successfully: {target_path}")
    print(f"Total records: {len(rows)}")


# =========================================================
# 5. NETWORK INTERFACE DETECTION (WINDOWS & LINUX)
# =========================================================

def _get_windows_adapters():
    if not sys.platform.startswith("win"):
        return []
    try:
        from scapy.arch.windows import get_windows_if_list
        return get_windows_if_list()
    except ImportError:
        return []


def _safe_get_if_addr(interface):
    try:
        addr = get_if_addr(interface)
        return addr if addr and addr != "0.0.0.0" else None
    except Exception:
        return None


def list_network_interfaces():
    """Return available interfaces as dicts with id, name, description, and ips."""
    available = get_if_list()
    win_adapters = _get_windows_adapters()
    interfaces = []

    if win_adapters:
        matched_ids = set()
        for adapter in win_adapters:
            guid = str(adapter.get("guid", "")).strip("{}").lower()
            iface_id = next(
                (iface for iface in available if guid and guid in iface.lower()),
                None,
            )
            if not iface_id:
                continue
            matched_ids.add(iface_id)
            ips = [ip for ip in adapter.get("ips", []) if ip]
            if not ips:
                addr = _safe_get_if_addr(iface_id)
                if addr:
                    ips = [addr]
            interfaces.append({
                "id": iface_id,
                "name": adapter.get("name") or iface_id,
                "description": adapter.get("description", ""),
                "ips": ips,
            })

        for iface_id in available:
            if iface_id not in matched_ids:
                addr = _safe_get_if_addr(iface_id)
                interfaces.append({
                    "id": iface_id,
                    "name": iface_id,
                    "description": "",
                    "ips": [addr] if addr else [],
                })
    else:
        for iface_id in available:
            addr = _safe_get_if_addr(iface_id)
            interfaces.append({
                "id": iface_id,
                "name": iface_id,
                "description": "",
                "ips": [addr] if addr else [],
            })

    return interfaces


def print_network_interfaces():
    interfaces = list_network_interfaces()
    if not interfaces:
        print("No network interfaces detected.")
        return

    print("\n===== AVAILABLE NETWORK INTERFACES =====")
    for idx, iface in enumerate(interfaces, start=1):
        ips = ", ".join(iface["ips"]) if iface["ips"] else "No IP"
        label = iface["name"]
        if iface["id"] != label:
            print(f"{idx}. {label} ({iface['id']}) - IPs: {ips}")
        else:
            print(f"{idx}. {label} - IPs: {ips}")


def _is_valid_ipv4(ip):
    return (
        isinstance(ip, str)
        and "." in ip
        and not ip.startswith("127.")
        and not ip.startswith("169.254.")
        and ip != "0.0.0.0"
    )


def resolve_capture_interface(requested_interface=None):
    interfaces = list_network_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No network interfaces found. Ensure Npcap/libpcap is installed "
            "and you have sufficient permissions."
        )

    # Manual interface selection
    if requested_interface:
        req_lower = requested_interface.strip().lower()
        for iface in interfaces:
            if (
                iface["id"].lower() == req_lower
                or iface["name"].lower() == req_lower
                or (iface["description"] and iface["description"].lower() == req_lower)
            ):
                return iface["id"]

        available_summary = ", ".join(
            f"{i['name']} ({', '.join(i['ips']) or 'No IP'})"
            for i in interfaces
        )
        raise RuntimeError(
            f"Network interface '{requested_interface}' not found. "
            f"Available interfaces: {available_summary}"
        )

    # First choice: interface used by the default route
    try:
        route_iface, source_ip, _ = conf.route.route("0.0.0.0")
        route_iface_str = str(route_iface).lower()

        for iface in interfaces:
            if (
                iface["id"].lower() == route_iface_str
                or iface["name"].lower() == route_iface_str
                or (source_ip and source_ip in iface["ips"])
            ):
                print(f"Default route interface detected: {iface['name']}")
                return iface["id"]
    except Exception as error:
        print(f"Default route detection failed: {error}")

    # Fallback: active non-virtual interface with a routable IPv4 address
    excluded_keywords = (
        "loopback", "vmware", "virtualbox", "hyper-v", "wan miniport",
        "npcap", "bluetooth", "wi-fi direct", "wintun", "tap-windows",
        "docker", "veth", "virbr", "vmnet", "vboxnet", "br-", "tun", "tap", "wg",
    )

    candidates = []
    for iface in interfaces:
        text = f"{iface['name']} {iface['description']}".lower()
        is_virtual = iface["id"].lower() == "lo" or any(
            kw in text for kw in excluded_keywords
        )
        has_ipv4 = any(_is_valid_ipv4(ip) for ip in iface["ips"])
        if has_ipv4 and not is_virtual:
            candidates.append(iface)

    if not candidates:
        raise RuntimeError(
            "No suitable active network interface was found. "
            "Use --list-interfaces and specify one with --interface."
        )

    for iface in candidates:
        name_lower = iface["name"].lower()
        if any(k in name_lower for k in ("wi-fi", "wifi", "wireless", "wlan")):
            return iface["id"]

    return candidates[0]["id"]


# =========================================================
# 6. LIVE PACKET CAPTURE
# =========================================================

def capture_live(
    duration=30,
    requested_interface=None,
    csv_output=None,
    pcap_output=None,
    max_packets=None,
    bpf_filter=None,
):
    if duration is not None and duration <= 0:
        raise ValueError("Capture duration must be greater than zero.")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("Maximum packet count must be greater than zero.")
    if bpf_filter is not None:
        if not isinstance(bpf_filter, str):
            raise ValueError("BPF filter must be a string.")
        bpf_filter = bpf_filter.strip() or None

    interface = resolve_capture_interface(requested_interface)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_csv = f"data/processed/live_traffic_{timestamp}.csv"
    default_pcap = f"data/processed/live_capture_{timestamp}.pcap"

    csv_path = _ensure_unique_path(csv_output or default_csv)
    pcap_path = _ensure_unique_path(pcap_output or default_pcap)

    try:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise RuntimeError(f"Failed to create output directory: {error}") from error

    protocol_counter = Counter()
    packet_count = 0

    print("\n===== TRAWIQ LIVE CAPTURE =====")
    print(f"Selected interface: {interface}")
    print(f"Capture duration: {duration if duration else 'unlimited'} seconds")
    if max_packets:
        print(f"Max packets: {max_packets}")
    if bpf_filter:
        print(f"BPF filter: {bpf_filter}")
    print("Starting packet capture (press Ctrl+C to stop)...\n")

    pcap_writer = None
    csvfile = None
    interrupted = False

    try:
        pcap_writer = PcapWriter(str(pcap_path), append=False, sync=True)
        csvfile = open(csv_path, "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csvfile, fieldnames=PACKET_FIELDS)
        csv_writer.writeheader()
        csvfile.flush()

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
            count=max_packets or 0,
            filter=bpf_filter,
        )

    except KeyboardInterrupt:
        interrupted = True
        print("\nCapture interrupted by user (Ctrl+C). Saving captured packets...")
    except PermissionError as error:
        raise PermissionError(
            f"Insufficient permissions to capture on '{interface}'. "
            f"Run as administrator/root or check capture privileges: {error}"
        ) from error
    except (Scapy_Exception, OSError, ValueError) as error:
        raise RuntimeError(
            f"Live capture failed on '{interface}': {error}"
        ) from error
    finally:
        if csvfile is not None:
            try:
                csvfile.flush()
                csvfile.close()
            except OSError as error:
                print(f"Warning: failed to close CSV file '{csv_path}': {error}")
        if pcap_writer is not None:
            try:
                pcap_writer.close()
            except Exception as error:
                print(f"Warning: failed to close PCAP file '{pcap_path}': {error}")

    status = "INTERRUPTED" if interrupted else "COMPLETED"
    print(f"\n===== LIVE CAPTURE RESULTS ({status}) =====")
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
        "--count",
        type=int,
        default=None,
        help="Maximum number of packets to capture in live mode",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Optional BPF filter expression (e.g., 'tcp', 'udp port 53')",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Optional network interface name",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default="data/raw/sample.pcap",
        help="PCAP file to analyze",
    )
    parser.add_argument(
        "--csv-output",
        type=str,
        default=None,
        help="Optional output CSV path",
    )
    parser.add_argument(
        "--pcap-output",
        type=str,
        default=None,
        help="Optional output PCAP path for live capture",
    )

    args = parser.parse_args()

    try:
        if args.list_interfaces:
            print_network_interfaces()
        elif args.live:
            capture_live(
                duration=args.duration,
                requested_interface=args.interface,
                csv_output=args.csv_output,
                pcap_output=args.pcap_output,
                max_packets=args.count,
                bpf_filter=args.filter,
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
                csv_target = args.csv_output or "data/processed/network_traffic.csv"
                export_to_csv(file_path, csv_target)
                print("\nTRAWIQ Security Analysis Completed!")

    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
    except Exception as error:
        print(f"\nError: {error}")
