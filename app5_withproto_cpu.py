import os
import time
import numpy as np
import multiprocessing as mp
import tkinter as tk
from tkinter import filedialog
from scapy.all import rdpcap, IP

# Optimized packet processing with multiprocessing (including protocol counts)
def process_packet_chunk(chunk_data):
    """Process packets and check for DDoS (including IP and Protocol analysis)"""
    ip_counts = np.zeros(10000, dtype=int)  # Array for IP frequency
    proto_counts = np.zeros(256, dtype=int)  # Array for protocol frequency
    suspicious_ips = set()
    suspicious_protocols = set()
    burst_count = 0
    last_time = None

    for packet in chunk_data:
        if IP in packet:
            src_ip = packet[IP].src
            proto = packet[IP].proto

            # Efficient IP counting using hashing
            ip_hash = hash(src_ip) % 10000
            ip_counts[ip_hash] += 1
            proto_counts[proto] += 1

            # Quick threshold check for high traffic IPs
            if ip_counts[ip_hash] > 1000:
                suspicious_ips.add(src_ip)

            # Quick threshold check for anomalous protocol traffic
            if proto_counts[proto] > 1000:
                suspicious_protocols.add(proto)

            # Burst detection (if packets arrive too quickly)
            curr_time = float(packet.time)
            if last_time and (curr_time - last_time) < 0.1:
                burst_count += 1
            last_time = curr_time

            # **Early exit** if attack detected (either high traffic IP or suspicious protocol)
            if len(suspicious_ips) > 0 or len(suspicious_protocols) > 0:
                return True  # DDoS detected

    return False  # No DDoS detected

def analyze_pcap(file_path):
    """Load PCAP file and analyze it with multiprocessing"""
    if not os.path.exists(file_path):
        print("File not found!")
        return False

    try:
        total_start = time.time()
        print("Loading PCAP file...")

        # Read packets once to minimize disk I/O
        packets = rdpcap(file_path)
        total_packets = len(packets)
        print(f"Total packets: {total_packets}")

        # Determine number of processes (use available CPU cores)
        #num_processes = min(mp.cpu_count(), 4)   Use max 4 cores to balance performance
        num_processes =4
        chunk_size = total_packets // num_processes
        packet_chunks = [packets[i:i + chunk_size] for i in range(0, total_packets, chunk_size)]

        print(f"Processing with {num_processes} processes...")

        process_start = time.time()

        # Multiprocessing Pool (stops early if DDoS found)
        with mp.Pool(num_processes) as pool:
            for result in pool.imap_unordered(process_packet_chunk, packet_chunks):
                if result:  # If any process detects DDoS, stop all
                    pool.terminate()
                    print("\n DDoS Attack Detected! ")
                    process_time = time.time() - process_start
                    print(f"Processing completed in {process_time:.2f} seconds.")
                    return True

        process_time = time.time() - process_start
        print(f"Processing completed in {process_time:.2f} seconds.")

        print("No DDoS attack detected.")
        return False

    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return False

def main():
    """Tkinter file selection"""
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[("PCAP files", "*.pcap")]
    )

    if file_path:
        analyze_pcap(file_path)
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()
