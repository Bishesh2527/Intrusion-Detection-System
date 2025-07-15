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

def main():
    dashboard = Dashboard()
    while True:
        choice = dashboard.show()
        if choice == "4":
            print("Exiting IDS.")
            break


        print("Starting IDS. Press Ctrl+C to stop.")
        try:
            pass
        except KeyboardInterrupt:
            print("IDS stopped by user.")

if __name__ == "__main__":
    main()