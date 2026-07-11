import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

def parse_log_file(file_path):
    total_lines = 0
    corrupted_lines = 0

    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            total_lines += 1
            line = line.strip()

            match = LOG_PATTERN.match(line)

            if not match:
                corrupted_lines += 1
                print(match)
                continue

            data = match.groupdict()

            print(f"IP: {data['ip']}")
            print(f"Time: {data['time']}")
            print(f"Method: {data['method']}")
            print(f"Path: {data['path']}")
            print(f"Protocol: {data['protocol']}")
            print(f"Status: {data['status']}")
            print(f"Size: {data['size']}")

    print(f"Total lines processed: {total_lines}")
    print(f"Corrupted lines skipped: {corrupted_lines}")

parse_log_file("test_access.log")
