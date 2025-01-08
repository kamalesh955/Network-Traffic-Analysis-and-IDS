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
  ```
  OR
  ```bash
  pip install -r requirements.txt
  ```
### Installation
- **Clone the repository**:

```bash
git clone https://github.com/kamalesh955/Network-Traffic-Analysis-and-IDS.git
```
 **Run the code**:

```bash
python app.py
```

-**Select the PCAP file via the file dialog box.**:

-**View extracted features and generated visualizations**:

-**Analyze results for potential DDoS attacks.**:


