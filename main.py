from datetime import datetime
from collections import Counter


def read_logs(filename):
    """Read log entries from a file."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            logs = file.readlines()
        return logs

    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return []


def analyze_logs(logs):
    """Analyze logs and report unusual activity."""

    print("=" * 50)
    print("         PYTHON LOG ANOMALY DETECTOR")
    print("=" * 50)

    log_counts = Counter()
    error_count = 0
    critical_count = 0
    error_messages = Counter()
    warning_messages = Counter()

    for log in logs:
        log = log.strip()

        if not log:
            continue

        print(log)

        if "INFO" in log:
            log_counts["INFO"] += 1
        elif "WARNING" in log:
            log_counts["WARNING"] += 1

            warning_message = log.split("WARNING", 1)[1].strip()
            warning_messages[warning_message] += 1
        elif "ERROR" in log:
             log_counts["ERROR"] += 1
             error_count += 1

             error_message = log.split("ERROR", 1)[1].strip()
             error_messages[error_message] += 1
            
        elif "CRITICAL" in log:
            log_counts["CRITICAL"] += 1
            critical_count += 1

    print("\n" + "=" * 50)
    print("                ANALYSIS REPORT")
    print("=" * 50)

    print(f"Total log entries: {sum(log_counts.values())}")
    print(f"Info messages: {log_counts['INFO']}")
    print(f"Warnings: {log_counts['WARNING']}")
    print(f"Errors: {error_count}")
    print(f"Critical events: {critical_count}")
    print("\n--- SECURITY ALERTS ---")

    for message, count in warning_messages.items():
        if "failed login" in message.lower() and count >= 3:
            print(f"SECURITY ALERT: {count} failed login attempts detected!") 
    print("\n--- MOST FREQUENT ERRORS ---")

    if error_messages:
        for message, count in error_messages.most_common():
            print(f"{message}: {count} time(s)")
    else:
        print("No errors found.")
    if error_count >= 3:
        print("\nALERT: Unusual number of errors detected!")

    if critical_count > 0:
        print("ALERT: A critical event was detected!")

    print("\nAnalysis completed at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


if __name__ == "__main__":

    print("\nPYTHON LOG ANOMALY DETECTOR")
    print("-" * 35)

    print("1. Server Logs")
    print("2. Database Logs")
    print("3. Security Logs")

    choice = input("\nChoose a log file (1-3): ").strip()

    log_files = {
        "1": "server.log",
        "2": "database.log",
        "3": "security.log"
    }

    if choice in log_files:
        selected_file = log_files[choice]

        print(f"\nAnalyzing: {selected_file}\n")

        server_logs = read_logs(selected_file)

        if server_logs:
            analyze_logs(server_logs)
        else:
            print("No logs available to analyze.")

    else:
        print("Invalid choice! Please select 1, 2, or 3.")