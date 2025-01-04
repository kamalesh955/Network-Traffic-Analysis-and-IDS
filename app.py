import os
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter
import tkinter as tk
from tkinter import filedialog
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud

# Function to extract features from PCAP file using Scapy
def extract_features_from_pcap(file_path):
    if not os.path.exists(file_path):
        print("File path does not exist. Please check the file path.")
        return None, None, None

    print(f"Processing the PCAP file: {file_path}")

    features = []

    try:
        packets = rdpcap(file_path)

        ip_counts = Counter()
        protocol_counts = Counter()

        last_packet_time = None
        burst_threshold = 0.1
        burst_count = 0

        for packet in packets:
            try:
                if packet.haslayer(IP):
                    feature = {
                        "Source IP": packet['IP'].src,
                        "Destination IP": packet['IP'].dst,
                        "Packet Length": len(packet),
                        "Protocol": packet.proto,
                        "Time": packet.time,
                    }

                    if packet.haslayer(TCP):
                        feature["Source Port"] = packet['TCP'].sport
                        feature["Destination Port"] = packet['TCP'].dport
                    elif packet.haslayer(UDP):
                        feature["Source Port"] = packet['UDP'].sport
                        feature["Destination Port"] = packet['UDP'].dport
                    elif packet.haslayer(ICMP):
                        feature["Source Port"] = 'N/A'
                        feature["Destination Port"] = 'N/A'

                    protocol_counts[packet.proto] += 1
                    ip_counts[packet['IP'].src] += 1

                    if last_packet_time is not None and (packet.time - last_packet_time) < burst_threshold:
                        burst_count += 1
                    last_packet_time = packet.time

                    features.append(feature)

            except Exception as e:
                continue

        total_packets = len(packets)
        total_burst_traffic = burst_count / total_packets if total_packets > 0 else 0

        df = pd.DataFrame(features)
        df['Total Packets'] = total_packets
        df['Burst Traffic Ratio'] = total_burst_traffic
        df['Unique Source IPs'] = len(ip_counts)
        df['Protocol Counts'] = dict(protocol_counts)

        return df, ip_counts, protocol_counts

    except Exception as e:
        print(f"Error processing the PCAP file: {e}")
        return None, None, None


# Function to detect possible DDoS activity
def detect_ddos(ip_counts, protocol_counts):
    threshold_ip = 1000
    high_traffic_ips = [ip for ip, count in ip_counts.items() if count > threshold_ip]

    threshold_protocol = 10000
    anomalous_protocols = {proto: count for proto, count in protocol_counts.items() if count > threshold_protocol}

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


# Function to visualize data
def visualize_data(df, protocol_counts):
    # Burst traffic ratio
    plt.figure(figsize=(8, 5))
    sns.histplot(df['Burst Traffic Ratio'], bins=10, kde=True)
    plt.title("Burst Traffic Ratio Distribution")
    plt.xlabel("Burst Traffic Ratio")
    plt.ylabel("Frequency")
    plt.show()

    plt.figure(figsize=(8, 5))
    sns.histplot(df['Packet Length'], bins=20, kde=True, color='blue')
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Length (bytes)")
    plt.ylabel("Frequency")
    plt.show()

    # 2. Protocol Distribution (Bar Plot)
    plt.figure(figsize=(12, 6))
    # Protocol distribution without palette causing deprecation warning
    sns.barplot(x=list(protocol_counts.keys()), y=list(protocol_counts.values()))
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.show()




# Main function
def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    file_path = filedialog.askopenfilename(title="Select a PCAP File", filetypes=[("PCAP files", "*.pcap")])

    if file_path:
        print(f"Selected file: {file_path}")
        features_df, ip_counts, protocol_counts = extract_features_from_pcap(file_path)

        if features_df is not None:
            print("Features extracted successfully!")
            print(features_df.head())

            # Visualize data
            visualize_data(features_df, protocol_counts)

            # Check for DDoS
            detect_ddos(ip_counts, protocol_counts)

            # Calculate accuracy
        else:
            print("No features were extracted. Please check the PCAP file.")
    else:
        print("No file was selected.")


if __name__ == "__main__":
    main()
