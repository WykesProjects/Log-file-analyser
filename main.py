"""
Windows Defender Firewall Log Analyser
--------------------------------------
Parses Windows Firewall logs, summarises:
- Action counts (ALLOW / DENY)
- Top 5 source IPs
- Top 5 destination ports
- Lists of IPs for SEND and RECEIVE
- Suspicious ports (445, 3389, 22, etc.)
"""

from collections import Counter


def parse_firewall_log(file_path: str):
    src_ip_counter = Counter()
    dst_port_counter = Counter()
    action_counter = Counter()
    send_ips = set()
    receive_ips = set()

    # Ports of concern
    suspicious_ports = {"445", "3389", "22", "23"}  # SMB, RDP, SSH, Telnet

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                # Skip comments or headers starting with "#"
                if line.startswith("#") or line.strip() == "":
                    continue

                parts = line.split()
                if len(parts) < 8:
                    continue  # Skip malformed lines

                date, time, action, protocol, src_ip, dst_ip, src_port, dst_port = parts[:8]

                # Count actions
                action_counter[action] += 1

                # Track source IPs and destination ports
                src_ip_counter[src_ip] += 1
                dst_port_counter[dst_port] += 1

                # Track send and/or receive IPs based on keyword at end of line
                if line.strip().endswith("SEND"):
                    send_ips.add(src_ip)
                elif line.strip().endswith("RECEIVE"):
                    receive_ips.add(dst_ip)

    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return

    # --- Report ---
    print(" Action counts:")
    for action, count in action_counter.items():
        print(f"   {action}: {count}")

    print("\n Top 5 most common source IPs:")
    for ip, count in src_ip_counter.most_common(5):
        print(f"   {ip}: {count} connections")

    print("\n Top 5 destination ports:")
    for port, count in dst_port_counter.most_common(5):
        print(f"   Port {port}: {count} connections")

    print("\n List of IPs for SEND:")
    for ip in send_ips:
        print(f"   {ip}")
    print(f"   Total: {len(send_ips)} IPs")

    print("\n List of IPs for RECEIVE:")
    for ip in receive_ips:
        print(f"   {ip}")
    print(f"   Total: {len(receive_ips)} IPs")

    print("\n List of IPs/port ranges of concern:")
    flagged = False
    for port, count in dst_port_counter.items():
        if port in suspicious_ports:
            print(f"   Port {port}: {count} connections")
            flagged = True
    if not flagged:
        print("   None flagged")


if __name__ == "__main__":
    log_file = "pfirewall.log"  # Example log file
    parse_firewall_log(log_file)