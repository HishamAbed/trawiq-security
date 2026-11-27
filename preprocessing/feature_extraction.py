
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd

from scapy.all import (
    PcapReader,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
)


# =====================================================
# TRAWIQ SECURITY - FLOW FEATURE EXTRACTION
# =====================================================

INPUT_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed/flows")

FLOW_TIMEOUT = 120

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# =====================================================
# 1. PACKET INFORMATION
# =====================================================

def get_packet_info(packet):
    """Extract information from supported network packets."""

    # ARP packets are counted separately.
    if ARP in packet:
        return {
            "packet_type": "ARP",
            "src_ip": packet[ARP].psrc,
            "dst_ip": packet[ARP].pdst,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ARP",
            "timestamp": float(packet.time),
            "packet_length": len(packet),
            "flags": 0,
        }

    # IPv4
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_number = packet[IP].proto

    # IPv6
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        protocol_number = packet[IPv6].nh

    else:
        return None

    src_port = 0
    dst_port = 0
    flags = 0

    # TCP
    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        flags = int(packet[TCP].flags)

    # UDP
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    # IPv4 ICMP
    elif ICMP in packet:
        protocol = "ICMP"

    # IPv6 ICMP, including extension-header cases
    elif (
        IPv6 in packet
        and (
            protocol_number == 58
            or any(
                getattr(layer, "__name__", "").startswith("ICMPv6")
                for layer in packet.layers()
            )
        )
    ):
        protocol = "ICMPv6"

    else:
        protocol = f"IP-{protocol_number}"

    return {
        "packet_type": "IP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": float(packet.time),
        "packet_length": len(packet),
        "flags": flags,
    }


# =====================================================
# 2. FLOW KEY
# =====================================================

def get_flow_key(info):
    """Create a bidirectional flow key."""

    source = (
        info["src_ip"],
        info["src_port"],
    )

    destination = (
        info["dst_ip"],
        info["dst_port"],
    )

    endpoint_a, endpoint_b = sorted(
        [source, destination]
    )

    return (
        endpoint_a,
        endpoint_b,
        info["protocol"],
    )


# =====================================================
# 3. CREATE FLOW
# =====================================================

def create_flow(info):
    """Initialize a new network flow."""

    return {
        "src_ip": info["src_ip"],
        "dst_ip": info["dst_ip"],

        "src_port": info["src_port"],
        "dst_port": info["dst_port"],

        "protocol": info["protocol"],

        "initiator": (
            info["src_ip"],
            info["src_port"],
        ),

        "responder": (
            info["dst_ip"],
            info["dst_port"],
        ),

        "start_time": info["timestamp"],
        "last_time": info["timestamp"],

        "timestamps": [],

        "fwd_lengths": [],
        "bwd_lengths": [],

        "fwd_flags": [],
        "bwd_flags": [],

        # TCP connection state
        "fin_sources": set(),
    }


# =====================================================
# 4. ADD PACKET TO FLOW
# =====================================================

def add_packet_to_flow(flow, info):
    """Add a packet to its forward or backward direction."""

    source = (
        info["src_ip"],
        info["src_port"],
    )

    direction = (
        "fwd"
        if source == flow["initiator"]
        else "bwd"
    )

    timestamp = info["timestamp"]

    flow["timestamps"].append(timestamp)

    flow[f"{direction}_lengths"].append(
        info["packet_length"]
    )

    flow[f"{direction}_flags"].append(
        info["flags"]
    )

    # Handle timestamps safely, including out-of-order packets.
    flow["start_time"] = min(
        flow["start_time"],
        timestamp,
    )

    flow["last_time"] = max(
        flow["last_time"],
        timestamp,
    )


# =====================================================
# 5. TCP CONNECTION MANAGEMENT
# =====================================================

def should_close_tcp_flow(flow, info):
    """
    Determine whether a TCP flow should be closed.

    RST:
        Close immediately.

    FIN:
        Close after both endpoints send FIN.
    """

    if info["protocol"] != "TCP":
        return False

    flags = info["flags"]

    # RST flag
    if flags & 0x04:
        return True

    # FIN flag
    if flags & 0x01:

        source = (
            info["src_ip"],
            info["src_port"],
        )

        flow["fin_sources"].add(source)

        # Both endpoints have sent FIN.
        if len(flow["fin_sources"]) >= 2:
            return True

    return False


# =====================================================
# 6. EXTRACT FLOWS
# =====================================================

def extract_flows(pcap_path):
    """
    Extract bidirectional flows from a PCAP file.

    Completed flows are preserved separately from
    currently active flows.
    """

    all_flows = []

    active_flows = {}

    packet_counts = Counter()

    unsupported_packets = []

    with PcapReader(str(pcap_path)) as packets:

        for packet in packets:

            info = get_packet_info(packet)

            # Unsupported packets
            if info is None:

                packet_counts["UNSUPPORTED"] += 1

                unsupported_packets.append(
                    packet.summary()
                )

                continue

            protocol = info["protocol"]

            packet_counts[protocol] += 1

            # ARP does not belong to IP 5-tuple flows.
            if info["packet_type"] == "ARP":
                continue

            key = get_flow_key(info)

            flow = active_flows.get(key)

            # Create a new flow if none exists.
            if flow is None:

                flow = create_flow(info)

                active_flows[key] = flow

                all_flows.append(flow)

            else:

                # Check inactivity timeout.
                time_difference = (
                    info["timestamp"] - flow["last_time"]
                )

                if time_difference > FLOW_TIMEOUT:

                    # Expire the previous flow.
                    active_flows.pop(key)

                    # Start a new flow.
                    flow = create_flow(info)

                    active_flows[key] = flow

                    all_flows.append(flow)

            # Add current packet before checking TCP closure.
            add_packet_to_flow(flow, info)

            # Handle TCP FIN and RST.
            if should_close_tcp_flow(flow, info):

                active_flows.pop(key, None)

    return (
        all_flows,
        packet_counts,
        unsupported_packets,
    )


# =====================================================
# 7. PACKET STATISTICS
# =====================================================

def calculate_stats(values, prefix):
    """Calculate maximum, minimum, mean and standard deviation."""

    values = np.asarray(
        values,
        dtype=float,
    )

    if len(values) == 0:
        return {
            f"{prefix}_max": 0,
            f"{prefix}_min": 0,
            f"{prefix}_mean": 0,
            f"{prefix}_std": 0,
        }

    return {
        f"{prefix}_max": float(np.max(values)),
        f"{prefix}_min": float(np.min(values)),
        f"{prefix}_mean": float(np.mean(values)),
        f"{prefix}_std": float(np.std(values)),
    }


# =====================================================
# 8. FLOW INTER ARRIVAL TIME
# =====================================================

def calculate_iat(timestamps):
    """Calculate inter-arrival time statistics."""

    timestamps = np.sort(
        np.asarray(
            timestamps,
            dtype=float,
        )
    )

    if len(timestamps) < 2:
        return {
            "flow_iat_mean": 0,
            "flow_iat_std": 0,
            "flow_iat_max": 0,
            "flow_iat_min": 0,
        }

    iat = np.diff(timestamps)

    return {
        "flow_iat_mean": float(np.mean(iat)),
        "flow_iat_std": float(np.std(iat)),
        "flow_iat_max": float(np.max(iat)),
        "flow_iat_min": float(np.min(iat)),
    }


# =====================================================
# 9. CALCULATE FLOW FEATURES
# =====================================================

def calculate_flow_features(flows):
    """Calculate statistical features for every flow."""

    records = []

    for flow in flows:

        fwd = np.asarray(
            flow["fwd_lengths"],
            dtype=float,
        )

        bwd = np.asarray(
            flow["bwd_lengths"],
            dtype=float,
        )

        all_lengths = np.concatenate(
            [fwd, bwd]
        )

        timestamps = np.asarray(
            flow["timestamps"],
            dtype=float,
        )

        if len(timestamps) == 0:
            continue

        duration = (
            float(np.max(timestamps) - np.min(timestamps))
        )

        total_packets = len(all_lengths)

        total_bytes = float(
            np.sum(all_lengths)
        )

        bytes_per_sec = (
            total_bytes / duration
            if duration > 0 else 0
        )

        packets_per_sec = (
            total_packets / duration
            if duration > 0 else 0
        )

        all_flags = (
            flow["fwd_flags"] +
            flow["bwd_flags"]
        )

        record = {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],

            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],

            "protocol": flow["protocol"],

            "flow_start_time": float(
                np.min(timestamps)
            ),

            "flow_duration": duration,

            "total_fwd_packets": len(fwd),
            "total_bwd_packets": len(bwd),

            "total_fwd_bytes": float(np.sum(fwd)),
            "total_bwd_bytes": float(np.sum(bwd)),

            "total_packets": total_packets,
            "total_bytes": total_bytes,

            "flow_bytes_per_sec": bytes_per_sec,
            "flow_packets_per_sec": packets_per_sec,

            "syn_count": sum(
                bool(x & 0x02)
                for x in all_flags
            ),

            "ack_count": sum(
                bool(x & 0x10)
                for x in all_flags
            ),

            "fin_count": sum(
                bool(x & 0x01)
                for x in all_flags
            ),

            "rst_count": sum(
                bool(x & 0x04)
                for x in all_flags
            ),

            "psh_count": sum(
                bool(x & 0x08)
                for x in all_flags
            ),

            "urg_count": sum(
                bool(x & 0x20)
                for x in all_flags
            ),
        }

        # All packet length statistics
        record.update(
            calculate_stats(
                all_lengths,
                "packet_length",
            )
        )

        # Forward packet length statistics
        record.update(
            calculate_stats(
                fwd,
                "fwd_packet_length",
            )
        )

        # Backward packet length statistics
        record.update(
            calculate_stats(
                bwd,
                "bwd_packet_length",
            )
        )

        # Flow inter-arrival time
        record.update(
            calculate_iat(timestamps)
        )

        records.append(record)

    return records


# =====================================================
# 10. PROCESS PCAP
# =====================================================

def process_pcap(pcap_path):
    """Process one PCAP file and export flow features."""

    print("\n" + "=" * 60)
    print("TRAWIQ SECURITY - FLOW FEATURE EXTRACTION")
    print("=" * 60)

    print("Input:", pcap_path)

    flows, packet_counts, unsupported = extract_flows(
        pcap_path
    )

    records = calculate_flow_features(flows)

    if records:

        df = pd.DataFrame(records)

        # Replace invalid numeric values.
        df.replace(
            [np.inf, -np.inf],
            0,
            inplace=True,
        )

        df.fillna(
            0,
            inplace=True,
        )

        output_path = (
            OUTPUT_DIR /
            f"{pcap_path.stem}_flows.csv"
        )

        df.to_csv(
            output_path,
            index=False,
            encoding="utf-8",
        )

        print("\nTotal flows:", len(df))

        print(
            "Total flow features:",
            len(df.columns),
        )

        print(
            "Flows CSV:",
            output_path,
        )

    else:

        print("\nNo IP flows found.")

    # Packet classification report
    print("\nPacket classification:")

    for protocol, count in sorted(
        packet_counts.items()
    ):

        print(
            f"{protocol}: {count}"
        )

    classified_total = sum(
        packet_counts.values()
    )

    print(
        "\nTotal classified packets:",
        classified_total,
    )

    print(
        "Unsupported packets:",
        len(unsupported),
    )

    if unsupported:

        print("\nUnsupported packet samples:")

        for item in unsupported[:5]:

            print("-", item)

    print("\nFlow extraction completed.")


# =====================================================
# 11. MAIN
# =====================================================

def main():

    pcap_files = sorted(
        INPUT_DIR.rglob("*.pcap")
    )

    if not pcap_files:

        print(
            "No PCAP files found in:",
            INPUT_DIR,
        )

        return

    print(
        "Found PCAP files:",
        len(pcap_files),
    )

    for pcap_file in pcap_files:

        try:

            process_pcap(pcap_file)

        except Exception as error:

            print(
                f"\nError processing {pcap_file.name}: {error}"
            )


if __name__ == "__main__":

    main()
