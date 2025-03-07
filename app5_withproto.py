import os
import time
import numpy as np
import tkinter as tk
from tkinter import filedialog
from scapy.all import rdpcap, IP
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Set
import cProfile

# Optimized packet processing with minimal operations
def process_packet_chunk(chunk_data: List) -> Tuple[Set[str], np.ndarray, np.ndarray, int]:
    """Optimized packet processing with minimal operations"""
    ip_counts = np.zeros(10000, dtype=int)  # Array to store IP counts
    proto_counts = np.zeros(256, dtype=int)  # Array to store protocol counts (max 256 protocols)
    burst_count = 0
    last_time = None
    suspicious_ips = set()

    # Process in batches for better memory efficiency
    for packet in chunk_data:
        if IP in packet:
            src_ip = packet[IP].src
            proto = packet[IP].proto

            # Efficient IP and protocol counting
            ip_hash = hash(src_ip) % 10000  # Use a simple hash for efficient indexing
            ip_counts[ip_hash] += 1
            proto_counts[proto] += 1

            # Quick threshold checks
            if ip_counts[ip_hash] > 1000:
                suspicious_ips.add(src_ip)

            # Simple burst detection
            curr_time = float(packet.time)
            if last_time and (curr_time - last_time) < 0.1:
                burst_count += 1
            last_time = curr_time

    return suspicious_ips, ip_counts, proto_counts, burst_count

def analyze_pcap(file_path: str) -> bool:
    if not os.path.exists(file_path):
        print("File not found!")
        return False

    try:
        total_start = time.time()
        print("Loading PCAP file...")

        # Read packets in one go to minimize disk I/O
        load_start = time.time()
        packets = rdpcap(file_path)
        load_time = time.time() - load_start
        print(f"File loaded in {load_time:.2f} seconds")

        total_packets = len(packets)

        # Stream processing and chunking
        num_threads = 4  # Using multiple threads for processing
        chunk_size = total_packets // num_threads

        packet_chunks = [
            packets[i:i + chunk_size]
            for i in range(0, total_packets, chunk_size)
        ]

        process_start = time.time()

        # Threaded parallel processing
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = list(executor.map(process_packet_chunk, packet_chunks))

        # Fast result aggregation
        suspicious_ips = set().union(*[r[0] for r in results])
        ip_counts = sum((r[1] for r in results), np.zeros(10000, dtype=int))
        proto_counts = sum((r[2] for r in results), np.zeros(256, dtype=int))
        total_bursts = sum(r[3] for r in results)

        process_time = time.time() - process_start
        total_time = time.time() - total_start

        # Detecting anomalous protocols (threshold = 1000 packets for demonstration)
        anomalous_protocols = [proto for proto, count in enumerate(proto_counts) if count > 1000]

        # High traffic IPs
        high_traffic_ips = [ip for ip in suspicious_ips if ip_counts[hash(ip) % 10000] > 1000]

        # Output results
        print(f"\nPerformance Metrics:")
        print(f"Load time: {load_time:.2f} seconds")
        print(f"Processing time: {process_time:.2f} seconds")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Processing speed: {total_packets / process_time:,.0f} packets/sec")

        if high_traffic_ips or anomalous_protocols:
            print("Potential DDoS attack detected!")
            if high_traffic_ips:
                print(f"High traffic from IPs: {high_traffic_ips}")
            if anomalous_protocols:
                print(f"Anomalous protocol traffic: {anomalous_protocols}")
            return True
        else:
            print("No DDoS attack detected.")
            return False

    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return False

def profile_analysis(file_path: str):
    # Create a Profile object
    profiler = cProfile.Profile()
    # Run the analysis under the profiler
    profiler.runctx('analyze_pcap(file_path)', globals(), {'analyze_pcap': analyze_pcap, 'file_path': file_path})
    # Save the stats
    profiler.dump_stats('profile_output')

def main():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP files", "*.pcap")]
    )

    if file_path:
        analyze_pcap(file_path)  # First run
    else:
        print("No file selected")

if __name__ == "__main__":
    main()
