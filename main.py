"""
Windows Defender Firewall Log Analyser
--------------------------------------
Parses Windows Firewall logs and produces a summary:
- Action counts (ALLOW / DROP)
- Top 5 source IPs
- Top 5 destination ports
- Lists of IPs for SEND and RECEIVE
- Suspicious ports (445, 3389, 22, 23)
"""

from collections import Counter
from datetime import datetime


def parse_firewall_log(file_path: str, output_path: str):
    src_ip_counter = Counter()
    dst_port_counter = Counter()
    action_counter = Counter()
    send_ips = set()
    receive_ips = set()

    suspicious_ports = {"445", "3389", "22", "23"}  # SMB, RDP, SSH, Telnet
    total_entries = 0

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or line.strip() == "":
                    continue

                parts = line.split()
                if len(parts) < 8:
                    continue

                _, _, action, protocol, src_ip, dst_ip, src_port, dst_port = parts[:8]

                action_counter[action] += 1
                src_ip_counter[src_ip] += 1
                dst_port_counter[dst_port] += 1
                total_entries += 1

                if line.strip().endswith("SEND"):
                    send_ips.add(src_ip)
                elif line.strip().endswith("RECEIVE"):
                    receive_ips.add(dst_ip)

    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return

    report_lines = []

    report_lines.append("Action counts:")
    for action, count in action_counter.items():
        report_lines.append(f"   {action}: {count}")

    report_lines.append("\nTop 5 most common source IPs:")
    for ip, count in src_ip_counter.most_common(5):
        report_lines.append(f"   {ip}: {count} connections")

    report_lines.append("\nTop 5 destination ports:")
    for port, count in dst_port_counter.most_common(5):
        report_lines.append(f"   Port {port}: {count} connections")

    report_lines.append("\nList of IPs for SEND:")
    for ip in sorted(send_ips):
        report_lines.append(f"   {ip}")
    report_lines.append(f"   Total: {len(send_ips)} IPs")

    report_lines.append("\nList of IPs for RECEIVE:")
    for ip in sorted(receive_ips):
        report_lines.append(f"   {ip}")
    report_lines.append(f"   Total: {len(receive_ips)} IPs")

    report_lines.append("\nList of IPs/port ranges of concern:")
    flagged = False
    for port, count in dst_port_counter.items():
        if port in suspicious_ports:
            report_lines.append(f"   Port {port}: {count} connections")
            flagged = True
    if not flagged:
        report_lines.append("   None flagged")

    # Add footer with timestamp and total entries
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines.append(f"\n✅ Analysis complete: {total_entries} entries processed")
    report_lines.append(f"Run on: {now}")

    # Print and save
    print("\n".join(report_lines))

    try:
        with open(output_path, "w", encoding="utf-8") as out_file:
            out_file.write("\n".join(report_lines))
        print(f"\nReport written to {output_path}")
    except Exception as e:
        print(f"Could not write report: {e}")


if __name__ == "__main__":
    log_file = input("Enter path to firewall log file: ").strip()
    output_file = input("Enter path to save the output report (e.g., report.txt): ").strip()

    if not log_file:
        log_file = "pfirewall.log"
    if not output_file:
        output_file = "report.txt"

    parse_firewall_log(log_file, output_file)