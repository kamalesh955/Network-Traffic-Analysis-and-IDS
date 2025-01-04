# PCAP Analysis and DDoS Detection  

A Python-based tool for analyzing network traffic from PCAP files. The tool extracts features using Scapy, visualizes traffic patterns, and identifies potential DDoS attacks.

## Features
- **Feature Extraction**: Extracts IP addresses, protocols, packet lengths, and burst traffic patterns from PCAP files.
- **Visualization**: Generates insightful visualizations using Matplotlib and Seaborn:
  - Protocol distribution
  - Burst traffic ratio
  - Potential DDoS traffic patterns
- **DDoS Detection**: Identifies potential DDoS attacks based on traffic anomalies.

---

## Getting Started

### Prerequisites
- **Python Version**: Python 3.8+
- **Required Libraries**:  
  Install the required libraries using pip:
  ```bash
  pip install scapy pandas matplotlib seaborn

### Installation
- **Clone the repository**:

```bash
git clone https://github.com/yourusername/pcap-analysis-ddos-detection.git
cd pcap-analysis-ddos-detection

- **Run the tool**:

```bash
python main.py

