from collections import defaultdict

SCAN_PORT_THRESHOLD = 10    # distinct denied ports from one IP
BRUTE_FORCE_THRESHOLD = 5   # denied attempts on login ports from one IP
LOGIN_PORTS = {22, 3389}    # SSH, RDP


def parse_line(line):
    parts = line.split()
    # Skipping bad lines keeps one corrupt entry from crashing the whole analysis.
    if len(parts) != 7:
        return None
    date, time, action, src, dst, port, proto = parts
    try:
        return {"time": f"{date} {time}", "action": action,
                "src": src, "dst": dst, "port": int(port), "proto": proto}
    except ValueError:
        return None


def analyze(path):
    # A set per IP stores only unique ports, so we can count distinct denied ports.
    denied_ports = defaultdict(set)
    # Repeated attempts on login ports points to brute force.
    login_denies = defaultdict(int)

    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if not event or event["action"] != "DENY":
                continue

            denied_ports[event["src"]].add(event["port"])
            if event["port"] in LOGIN_PORTS:
                login_denies[event["src"]] += 1

    findings = {}

    # Detection 1: port scan
    for ip, ports in denied_ports.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            findings[ip] = f"possible port scan ({len(ports)} distinct ports denied)"

    # Detection 2: brute force
    for ip, count in login_denies.items():
        if count >= BRUTE_FORCE_THRESHOLD and ip not in findings:
            findings[ip] = f"possible brute force attack ({count} denied attempts on login ports)"

    return findings


def main():
    findings = analyze("firewall.log")

    print("=== Suspicious sources ===")
    for ip, reason in findings.items():
        print(f"{ip}: {reason}")

    with open("blocklist.txt", "w") as f:
        f.write("\n".join(findings) + "\n")
    print(f"\n{len(findings)} IPs written to blocklist.txt")


if __name__ == "__main__":
    main()