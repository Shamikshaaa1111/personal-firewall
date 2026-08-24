import subprocess


def show_rules():
    subprocess.run(["sudo", "nft", "list", "table", "inet", "filter"])


def block_ip(ip):
    subprocess.run([
        "sudo", "nft", "add", "rule",
        "inet", "filter", "input",
        "ip", "saddr", ip, "counter", "drop"
    ])

    subprocess.run([
        "sudo", "nft", "add", "rule",
        "inet", "filter", "output",
        "ip", "daddr", ip, "counter", "drop"
    ])

    print(f"[+] Blocked IP: {ip}")


def block_port(port):
    subprocess.run([
        "sudo", "nft", "add", "rule",
        "inet", "filter", "input",
        "tcp", "dport", str(port), "counter", "drop"
    ])

    print(f"[+] Blocked TCP Port: {port}")


def unblock_ip(ip):
    result = subprocess.run(
        ["sudo", "nft", "-a", "list", "chain", "inet", "filter", "input"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        if f"ip saddr {ip}" in line and "handle" in line:
            handle = line.split("handle")[-1].strip()
            subprocess.run([
                "sudo", "nft", "delete", "rule",
                "inet", "filter", "input",
                "handle", handle
            ])

    result = subprocess.run(
        ["sudo", "nft", "-a", "list", "chain", "inet", "filter", "output"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        if f"ip daddr {ip}" in line and "handle" in line:
            handle = line.split("handle")[-1].strip()
            subprocess.run([
                "sudo", "nft", "delete", "rule",
                "inet", "filter", "output",
                "handle", handle
            ])

    print(f"[-] Unblocked IP: {ip}")


def unblock_port(port):
    result = subprocess.run(
        ["sudo", "nft", "-a", "list", "chain", "inet", "filter", "input"],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        if f"tcp dport {port}" in line and "handle" in line:
            handle = line.split("handle")[-1].strip()
            subprocess.run([
                "sudo", "nft", "delete", "rule",
                "inet", "filter", "input",
                "handle", handle
            ])

    print(f"[-] Unblocked TCP Port: {port}")


def main():
    while True:
        print("\n========== PERSONAL FIREWALL ==========")
        print("1. Show Firewall Rules")
        print("2. Block IP")
        print("3. Block Port")
        print("4. Unblock IP")
        print("5. Unblock Port")
        print("6. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            show_rules()

        elif choice == "2":
            ip = input("Enter IP to block: ")
            block_ip(ip)

        elif choice == "3":
            port = input("Enter port to block: ")
            block_port(port)

        elif choice == "4":
            ip = input("Enter IP to unblock: ")
            unblock_ip(ip)

        elif choice == "5":
            port = input("Enter port to unblock: ")
            unblock_port(port)

        elif choice == "6":
            print("Firewall closed.")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
