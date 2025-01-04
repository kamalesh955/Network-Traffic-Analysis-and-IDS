PCAP Analysis and DDoS Detection
A Python-based tool for analyzing network traffic from PCAP files. The tool extracts features using Scapy, visualizes traffic patterns, and identifies potential DDoS attacks.

Features
Feature Extraction: Extracts IP addresses, protocols, packet lengths, and burst traffic patterns from PCAP files.
Visualization: Generates beautiful and insightful visualizations using Matplotlib and Seaborn:
Protocol distribution
Burst traffic ratio
Potential DDoS traffic patterns
DDoS Detection: Identifies potential DDoS attacks based on traffic anomalies.
Getting Started
Prerequisites
Python 3.8+
Libraries: scapy, pandas, seaborn, matplotlib
Install the required libraries:

bash
Copy code
pip install scapy pandas matplotlib seaborn
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/pcap-analysis-ddos-detection.git
cd pcap-analysis-ddos-detection
Run the tool:

bash
Copy code
python main.py
Usage
Run the script and select the PCAP file via the file dialog box.
View the extracted features and generated visualizations.
Analyze results for potential DDoS attacks.
Visualizations
The tool includes the following visualizations:

Protocol Distribution: Displays the count of traffic for each protocol.
Burst Traffic Ratio Distribution: Shows the frequency distribution of burst traffic.
Potential DDoS Detection: Highlights IPs with suspicious traffic patterns.
