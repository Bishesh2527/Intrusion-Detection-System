# Intrusion Detection System (IDS)

## Overview

This project is a Python-based Intrusion Detection System (IDS) that monitors network traffic in real-time, analyzes packet flows, detects threats using both signature-based and anomaly-based methods, and generates alerts. The system is modular, extensible, and provides a dashboard for user interaction.

## Features

- **Packet Capture:** Uses Scapy to sniff packets from a selected network interface.
- **Traffic Analysis:** Aggregates packet statistics per flow and extracts relevant features.
- **Threat Detection:**
  - **Signature-based:** Detects known attack patterns (e.g., SYN flood, port scan, DDoS, unsecure downloads).
  - **Anomaly-based:** Uses Isolation Forest to identify abnormal traffic patterns.
- **Alert System:** Configurable to log alerts to console, file, or both. Alerts include threat type, confidence, and packet details.
- **Dashboard:** Interactive CLI dashboard for selecting alert preferences and network interface.
- **Interface Selection:** Lists available network interfaces and allows user selection.

## Requirements

- Python 3.7+
- [Scapy](https://scapy.net/)
- [scikit-learn](https://scikit-learn.org/)
- Numpy

Install dependencies:
```bash
pip install scapy scikit-learn numpy
```

## Usage

1. **Run the IDS:**
   ```bash
   python main.py
   ```

2. **Dashboard Options:**
   - **1:** Real-time alerts only (console)
   - **2:** Save alerts to file only
   - **3:** Both console and file logging
   - **4:** Exit

3. **Select Network Interface:**
   - The system lists available interfaces with IP addresses.
   - Enter the number corresponding to your desired interface.

4. **Monitoring:**
   - The IDS will start capturing and analyzing packets.
   - Alerts are generated based on detected threats.
   - Press `Ctrl+C` to stop monitoring.

## Code Structure

- **PacketCapture:** Handles packet sniffing and queuing.
- **TrafficAnalyzer:** Maintains flow statistics and extracts features from packets.
- **DetectionEngine:** Implements both signature-based and anomaly-based threat detection.
- **AlertSystem:** Manages alert generation and logging.
- **IntrusionDetectionSystem:** Orchestrates packet capture, analysis, detection, and alerting.
- **Dashboard:** Provides CLI for user interaction and configuration.
- **select_interface:** Utility for listing and selecting network interfaces.
- **main:** Entry point; manages dashboard and IDS lifecycle.

## Extending

- **Add new signature rules:** Modify `DetectionEngine.load_signature_rules()`.
- **Change anomaly detection:** Update Isolation Forest parameters or replace with another model.
- **Customize alerts:** Edit `AlertSystem.generate_alert()` for different alert formats or destinations.

## Logging

- Alerts are logged to `ids_alerts.log` when file logging is enabled.
- High-confidence threats are logged as critical.

## Disclaimer

This IDS is for educational and research purposes. It is not intended for production use without further testing and security hardening.

## License

MIT