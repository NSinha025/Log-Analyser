import re
import csv
from collections import Counter, defaultdict

# Define the threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 5

# Input and output file names
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

def parse_log_file(log_file):
    """Parse the log file and extract data."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = Counter()

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST) (/\S*) HTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Check for failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_csv):
    """Save results to a CSV file."""
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious IPs
        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(LOG_FILE)

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Identify suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

    # Display results
    print("Requests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")

if __name__ == '__main__':
    main()
