from scapy.all import get_if_list, get_if_addr

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


        print("Starting IDS. Press Ctrl+C to stop.")
        try:
            pass
        except KeyboardInterrupt:
            print("IDS stopped by user.")

if __name__ == "__main__":
    main()