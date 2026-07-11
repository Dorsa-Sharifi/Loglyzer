import re
from collections import Counter
import matplotlib.pyplot as plt
import argparse
import os
import sys
import gzip
import json

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_log_file(file_path, to_json=False):
    total_lines = 0
    corrupted_lines = 0

    total_requests = 0
    error_requests = 0

    ip_counter = Counter()
    endpoint_counter = Counter()
    hourly_counter = Counter()

    if file_path.endswith('.gz'):
        open_func = gzip.open
        open_mode = 'rt'
    else:
        open_func = open
        open_mode = 'r'

    with open_func(file_path, open_mode, encoding='utf-8') as file:
        for line in file:
            total_lines += 1
            line = line.strip()

            if not line:
                continue

            match = LOG_PATTERN.match(line)

            if not match:
                corrupted_lines += 1
                continue

            data = match.groupdict()

            if data['status'].startswith(('4', '5')):
                error_requests += 1

            total_requests += 1
            ip_counter[data['ip']] += 1
            endpoint_counter[data['path']] += 1

            time_parts = data['time'].split(':')
            hour_key = f"{time_parts[0]}:{time_parts[1]}"
            hourly_counter[hour_key] += 1

    if total_requests == 0:
        if to_json:
            print(json.dumps({
                "error": "No valid requests found in the log file.",
                "metrics": {"total_lines_processed": total_lines, "corrupted_lines_skipped": corrupted_lines}
            }, indent=4))
        else:
            print(f"Total lines processed: {total_lines}")
            print(f"Corrupted lines skipped: {corrupted_lines}")
            print(" No valid requests found in the log file.")
        return

    top_10_ips = ip_counter.most_common(10)
    top_10_endpoints = endpoint_counter.most_common(10)
    unique_ips_count = len(ip_counter)
    error_rate = (error_requests / total_requests) * 100

    if to_json:
        report_data = {
            "metrics": {
                "total_lines_processed": total_lines,
                "corrupted_lines_skipped": corrupted_lines,
                "total_requests": total_requests,
                "unique_ips_count": unique_ips_count,
                "error_rate_percentage": round(error_rate, 2)
            },
            "top_10_ips": [{"ip": ip, "count": count} for ip, count in top_10_ips],
            "top_10_endpoints": [{"path": path, "count": count} for path, count in top_10_endpoints]
        }
        print(json.dumps(report_data, indent=4))
    else:
        print(f"Total lines processed: {total_lines}")
        print(f"Corrupted lines skipped: {corrupted_lines}")
        print(f"Total requests: {total_requests}")
        print(f"Top 10 ips: {top_10_ips}")
        print(f"Top 10 endpoints: {top_10_endpoints}")
        print(f"Unique ips count: {unique_ips_count}")
        print(f"Error rate: {error_rate:.2f}%")

    plot_hourly_traffic(hourly_counter)


def plot_hourly_traffic(hourly_counter):
    if not hourly_counter:
        print("No traffic data to plot.")
        return

    hours = sorted(hourly_counter.keys())
    counts = [hourly_counter[hour] for hour in hours]

    plt.figure(figsize=(12, 6))

    plt.bar(hours, counts, color='skyblue', edgecolor='navy')

    plt.title("Hourly Traffic Distribution (Peak Analysis)", fontsize=14, fontweight='bold')
    plt.xlabel("Time (Hour)", fontsize=12)
    plt.ylabel("Number of Requests", fontsize=12)

    plt.xticks(rotation=45, ha='right')

    plt.grid(axis='y', linestyle='--', alpha=0.7)

    plt.tight_layout()

    plt.savefig("traffic_report.png", dpi=300)
    print("Graphical report saved as 'traffic_report.png'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Server Access Log Analyzer CLI Tool")

    parser.add_argument("logfile", nargs="?", default="access.log",
                        help="Path to the access log file (default: access.log)")

    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        print(f"Error: The file '{args.logfile}' does not exist.", file=sys.stderr)
        sys.exit(1)

    parse_log_file(args.logfile, to_json=args.json)