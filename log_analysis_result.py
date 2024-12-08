import re
import csv
from collections import defaultdict, Counter

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE_PATH = "sample.log"  # Replace with the actual log file path
OUTPUT_CSV = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Read and parse the log file."""
    with open(file_path, "r") as file:
        return file.readlines()

def count_requests_per_ip(log_lines):
    """Count requests per IP address."""
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    ip_counts = Counter()

    for line in log_lines:
        match = ip_pattern.search(line)
        if match:
            ip_counts[match.group()] += 1

    return ip_counts.most_common()

def most_frequent_endpoint(log_lines):
    """Identify the most frequently accessed endpoint."""
    endpoint_pattern = re.compile(r'"[A-Z]+\s(/[\w/.\-]*)\s')
    endpoint_counts = Counter()

    for line in log_lines:
        match = endpoint_pattern.search(line)
        if match:
            endpoint_counts[match.group(1)] += 1

    return endpoint_counts.most_common(1)[0] if endpoint_counts else None

def detect_suspicious_activity(log_lines):
    """Detect IPs with failed login attempts exceeding the threshold."""
    failed_login_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}.*(401|Invalid credentials)')
    failed_login_counts = Counter()

    for line in log_lines:
        if failed_login_pattern.search(line):
            ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
            if ip_match:
                failed_login_counts[ip_match.group()] += 1

    return [(ip, count) for ip, count in failed_login_counts.items() if count > FAILED_LOGIN_THRESHOLD]

def save_results_to_csv(ip_requests, top_endpoint, suspicious_activities):
    """Save analysis results to a CSV file."""
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_requests)

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if top_endpoint:
            writer.writerow([top_endpoint[0], top_endpoint[1]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_activities)

def main():
    log_lines = parse_log_file(LOG_FILE_PATH)

    # 1. Count requests per IP
    ip_requests = count_requests_per_ip(log_lines)
    print("Requests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<10}")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count:<10}")

    # 2. Most frequently accessed endpoint
    top_endpoint = most_frequent_endpoint(log_lines)
    if top_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    # 3. Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(log_lines)
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts':<10}")
    for ip, count in suspicious_activities:
        print(f"{ip:<20}{count:<10}")

    # 4. Save results to CSV
    save_results_to_csv(ip_requests, top_endpoint, suspicious_activities)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
