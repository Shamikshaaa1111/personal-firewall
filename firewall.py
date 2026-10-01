#!/usr/bin/env python3

import subprocess
import os
import re
import time


TABLE = "personal_firewall"
CHAIN = "input"


# ============================================================
# BASIC COMMAND FUNCTION
# ============================================================

def run_command(command):
    """Run a Linux command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            capture_output=True
        )

        if result.returncode != 0:
            return result.stderr.strip()

        return result.stdout.strip()

    except Exception as e:
        return str(e)


# ============================================================
# ROOT CHECK
# ============================================================

def check_root():
    if os.geteuid() != 0:
        print("\n[!] Please run the firewall using sudo.")
        print("    Example: sudo python3 firewall.py")
        exit()


# ============================================================
# CREATE FIREWALL
# ============================================================

def create_firewall():
    """Create the nftables table and input chain if they don't exist."""

    run_command(f"nft add table inet {TABLE}")

    run_command(
        f"nft 'add chain inet {TABLE} {CHAIN} "
        "{ type filter hook input priority 0; policy accept; }'"
    )

    print("[+] Firewall initialized.")

# ============================================================
# BLOCK IP
# ============================================================

def block_ip():
    ip = input("\nEnter IP to block: ").strip()

    if not valid_ip(ip):
        print("[!] Invalid IP address.")
        return

    # Check if already blocked
    rules = run_command(f"nft list chain inet {TABLE} {CHAIN}")

    if ip in rules:
        print(f"[!] IP {ip} is already blocked.")
        return

    command = (
        f"nft add rule inet {TABLE} {CHAIN} "
        f"ip saddr {ip} counter drop"
    )

    result = run_command(command)

    if result:
        print(f"[!] Error: {result}")
    else:
        print(f"[+] Blocked IP: {ip}")


# ============================================================
# BLOCK PORT
# ============================================================

def block_port():
    port = input("\nEnter port to block: ").strip()

    if not valid_port(port):
        print("[!] Invalid port number.")
        return

    rules = run_command(f"nft list chain inet {TABLE} {CHAIN}")

    if f"dport {port}" in rules:
        print(f"[!] Port {port} is already blocked.")
        return

    # Block TCP and UDP traffic on the port
    run_command(
        f"nft add rule inet {TABLE} {CHAIN} "
        f"tcp dport {port} counter drop"
    )

    run_command(
        f"nft add rule inet {TABLE} {CHAIN} "
        f"udp dport {port} counter drop"
    )

    print(f"[+] Blocked TCP/UDP port: {port}")


# ============================================================
# UNBLOCK IP
# ============================================================

def unblock_ip():
    ip = input("\nEnter IP to unblock: ").strip()

    if not valid_ip(ip):
        print("[!] Invalid IP address.")
        return

    rules = run_command(f"nft -a list chain inet {TABLE} {CHAIN}")

    found = False

    for line in rules.splitlines():

        if f"ip saddr {ip}" in line:

            match = re.search(r"# handle (\d+)", line)

            if match:
                handle = match.group(1)

                run_command(
                    f"nft delete rule inet {TABLE} {CHAIN} "
                    f"handle {handle}"
                )

                found = True

    if found:
        print(f"[+] Unblocked IP: {ip}")
    else:
        print(f"[!] IP {ip} was not found in the firewall rules.")


# ============================================================
# UNBLOCK PORT
# ============================================================

def unblock_port():
    port = input("\nEnter port to unblock: ").strip()

    if not valid_port(port):
        print("[!] Invalid port number.")
        return

    rules = run_command(f"nft -a list chain inet {TABLE} {CHAIN}")

    found = False

    for line in rules.splitlines():

        if f"dport {port}" in line:

            match = re.search(r"# handle (\d+)", line)

            if match:
                handle = match.group(1)

                run_command(
                    f"nft delete rule inet {TABLE} {CHAIN} "
                    f"handle {handle}"
                )

                found = True

    if found:
        print(f"[+] Unblocked port: {port}")
    else:
        print(f"[!] Port {port} was not found.")


# ============================================================
# SHOW FIREWALL RULES
# ============================================================

def show_rules():

    print("\n========== FIREWALL RULES ==========\n")

    rules = run_command(
        f"nft -a list chain inet {TABLE} {CHAIN}"
    )

    if not rules:
        print("[!] No firewall rules found.")
        return

    print(rules)


# ============================================================
# VIEW FIREWALL LOGS
# ============================================================

def view_logs():

    print("\n========== FIREWALL LOGS ==========\n")

    # Check kernel messages for nftables
    result = run_command(
        "journalctl -k --no-pager -n 30 2>/dev/null"
    )

    if result:
        lines = result.splitlines()

        firewall_lines = []

        for line in lines:
            if "nft" in line.lower() or "drop" in line.lower():
                firewall_lines.append(line)

        if firewall_lines:
            for line in firewall_lines:
                print(line)
        else:
            print("No recent firewall-related logs found.")

    else:
        print("[!] Unable to read system logs.")


# ============================================================
# MONITOR TRAFFIC
# ============================================================

def monitor_traffic():

    print("\n========== TRAFFIC MONITOR ==========")
    print("Monitoring network connections...")
    print("Press Ctrl+C to stop.\n")

    try:

        while True:

            print("-" * 60)
            print(time.strftime("%Y-%m-%d %H:%M:%S"))

            result = run_command(
                "ss -tun"
            )

            print(result)

            time.sleep(3)

    except KeyboardInterrupt:
        print("\n[+] Traffic monitoring stopped.")


# ============================================================
# PROTOCOL FILTERING
# ============================================================

def protocol_filtering():

    while True:

        print("\n========== PROTOCOL FILTERING ==========")
        print("1. Block TCP")
        print("2. Block UDP")
        print("3. Block ICMP")
        print("4. Unblock TCP")
        print("5. Unblock UDP")
        print("6. Unblock ICMP")
        print("7. Back")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":

            run_command(
                f"nft add rule inet {TABLE} {CHAIN} "
                "ip protocol tcp counter drop"
            )

            print("[+] TCP traffic blocked.")

        elif choice == "2":

            run_command(
                f"nft add rule inet {TABLE} {CHAIN} "
                "ip protocol udp counter drop"
            )

            print("[+] UDP traffic blocked.")

        elif choice == "3":

            run_command(
                f"nft add rule inet {TABLE} {CHAIN} "
                "ip protocol icmp counter drop"
            )

            print("[+] ICMP traffic blocked.")

        elif choice == "4":

            delete_protocol_rules("tcp")

        elif choice == "5":

            delete_protocol_rules("udp")

        elif choice == "6":

            delete_protocol_rules("icmp")

        elif choice == "7":
            break

        else:
            print("[!] Invalid choice.")


# ============================================================
# DELETE PROTOCOL RULE
# ============================================================

def delete_protocol_rules(protocol):

    rules = run_command(
        f"nft -a list chain inet {TABLE} {CHAIN}"
    )

    found = False

    for line in rules.splitlines():

        if f"ip protocol {protocol}" in line:

            match = re.search(r"# handle (\d+)", line)

            if match:

                handle = match.group(1)

                run_command(
                    f"nft delete rule inet {TABLE} {CHAIN} "
                    f"handle {handle}"
                )

                found = True

    if found:
        print(f"[+] {protocol.upper()} filtering removed.")
    else:
        print(f"[!] No {protocol.upper()} filtering rule found.")


# ============================================================
# FIREWALL STATUS
# ============================================================

def firewall_status():

    print("\n========== FIREWALL STATUS ==========\n")

    result = run_command(
        f"nft list table inet {TABLE}"
    )

    if "table" in result:

        print("Firewall Status : ACTIVE")
        print("Firewall Table  :", TABLE)
        print("Main Chain      :", CHAIN)

        rules = run_command(
            f"nft list chain inet {TABLE} {CHAIN}"
        )

        rule_count = 0

        for line in rules.splitlines():

            if "counter" in line or "drop" in line:
                rule_count += 1

        print("Rules            :", rule_count)

    else:

        print("Firewall Status : INACTIVE")


# ============================================================
# RULE COUNTERS
# ============================================================

def rule_counters():

    print("\n========== RULE COUNTERS ==========\n")

    result = run_command(
        f"nft -a list chain inet {TABLE} {CHAIN}"
    )

    if not result:
        print("[!] No rules found.")
        return

    found = False

    for line in result.splitlines():

        if "counter" in line:

            print(line)
            found = True

    if not found:
        print("[!] No counters available.")


# ============================================================
# VALIDATE IP
# ============================================================

def valid_ip(ip):

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:

        for part in parts:

            number = int(part)

            if number < 0 or number > 255:
                return False

        return True

    except ValueError:
        return False


# ============================================================
# VALIDATE PORT
# ============================================================

def valid_port(port):

    try:

        number = int(port)

        return 1 <= number <= 65535

    except ValueError:
        return False


# ============================================================
# MENU
# ============================================================

def show_menu():

    print("""
╔══════════════════════════════════════╗
║          PERSONAL FIREWALL           ║
╠══════════════════════════════════════╣
║ 1. Block IP                          ║
║ 2. Block Port                        ║
║ 3. Unblock IP                        ║
║ 4. Unblock Port                      ║
║ 5. Show Firewall Rules               ║
║ 6. View Firewall Logs                ║
║ 7. Monitor Traffic                   ║
║ 8. Protocol Filtering                ║
║ 9. Firewall Status                   ║
║ 10. Rule Counters                    ║
║ 11. Exit                             ║
╚══════════════════════════════════════╝
""")


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    check_root()

    create_firewall()

    while True:

        show_menu()

        choice = input("Enter choice: ").strip()

        if choice == "1":
            block_ip()

        elif choice == "2":
            block_port()

        elif choice == "3":
            unblock_ip()

        elif choice == "4":
            unblock_port()

        elif choice == "5":
            show_rules()

        elif choice == "6":
            view_logs()

        elif choice == "7":
            monitor_traffic()

        elif choice == "8":
            protocol_filtering()

        elif choice == "9":
            firewall_status()

        elif choice == "10":
            rule_counters()

        elif choice == "11":
            print("\n[+] Exiting Personal Firewall...")
            break

        else:
            print("\n[!] Invalid choice. Please enter 1-11.")

        input("\nPress Enter to continue...")


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":
    main()
