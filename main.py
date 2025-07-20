from scapy.all import sniff, IP, TCP, get_if_list, get_if_addr
from collections import defaultdict
import threading
import queue
import logging
import json
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            t = packet.time
            if not stats['start_time']:
                stats['start_time'] = t
            stats['last_time'] = t

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time'] or 1e-6
        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.anomaly_detector.fit([[100, 10, 1000], [200, 20, 1500], [50, 5, 500]])

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f: (f['tcp_flags'] == 2 and f['packet_rate'] > 100)
            },
            'port_scan': {
                'condition': lambda f: (f['packet_size'] < 100 and f['packet_rate'] > 50)
            },
            'ddos': {
                'condition': lambda f: (f['packet_rate'] > 1000)
            },
            'unsecure_download': {
                'condition': lambda f: (f['packet_size'] > 1000000 and f['packet_rate'] > 10 and f['tcp_flags'] == 24)
            }
        }

    def detect_threats(self, features):
        threats = []
        for rname, r in self.signature_rules.items():
            if r['condition'](features):
                threats.append({'type': 'signature', 'rule': rname, 'confidence': 1.0})

        vec = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
        score = self.anomaly_detector.score_samples(vec)[0]
        if score < -0.5:
            threats.append({'type': 'anomaly', 'score': score, 'confidence': min(1.0, abs(score))})

        return threats

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", to_console=True, to_file=True):
        self.to_console = to_console
        self.to_file = to_file
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)
        if to_file:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }
        alert_json = json.dumps(alert)
        if self.to_console:
            print(f"ALERT: {alert_json}")
        if self.to_file:
            self.logger.warning(alert_json)
            if threat.get('confidence', 0.0) > 0.8:
                self.logger.critical(f"High confidence threat detected: {alert_json}")

class Dashboard:
    def __init__(self):
        self.options = {
            "1": "Real-time alerts only (console)",
            "2": "Save alerts to file only",
            "3": "Both console and file logging",
            "4": "Exit"
        }

    def show(self):
        print("\n--- IDS Dashboard ---")
        for k, v in self.options.items():
            print(f"{k}. {v}")
        while True:
            choice = input("Select an option: ")
            if choice in self.options:
                return choice
            print("Invalid choice. Try again.")

def select_interface():
    interfaces = get_if_list()
    print("Available network interfaces (with IP or friendly names):")
    filtered = []

    for iface in interfaces:
        if "Loopback" in iface or "NPF_Loopback" in iface:
            continue

        try:
            ip = get_if_addr(iface)
        except:
            ip = "No IP"

        print(f"{len(filtered)}: {iface} - IP: {ip}")
        filtered.append(iface)

    if not filtered:
        print("No usable interfaces found.")
        return None

    while True:
        try:
            choice = int(input("Select interface number (e.g., 0 for eth, 1 for wlan): "))
            if 0 <= choice < len(filtered):
                return filtered[choice]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def main():
    dashboard = Dashboard()
    while True:
        choice = dashboard.show()
        if choice == "4":
            print("Exiting IDS.")
            break

        selected_iface = select_interface()
        if not selected_iface:
            print("Failed to select a valid interface. Exiting...")
            break

        if choice == "1":
            alert_system = AlertSystem(to_console=True, to_file=False)
        elif choice == "2":
            alert_system = AlertSystem(to_console=False, to_file=True)
        elif choice == "3":
            alert_system = AlertSystem(to_console=True, to_file=True)


        print("Starting IDS. Press Ctrl+C to stop.")
        try:
            pass
        except KeyboardInterrupt:
            print("IDS stopped by user.")

if __name__ == "__main__":
    main()