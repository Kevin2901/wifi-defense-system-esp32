# 🏗️ System Architecture - ESP32 Wi-Fi Defense

## Components
- **ESP32**: Hardware packet sniffer & anomaly detector
- **Sniffer Module**: Captures packets in promiscuous mode
- **Detection Engine**: Detects de-auth frames & anomalies
- **Logger**: Stores suspicious activity
- **Alert System**: Notifies admin in real time

## Future Additions
- AI-based anomaly detection
- Web dashboard
- Large-scale MANET deployment support

## Suggested Diagram
[ESP32] → [Sniffer] → [Detection Engine] → [Logger] → [Alerts]
