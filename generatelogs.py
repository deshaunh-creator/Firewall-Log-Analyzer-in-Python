#Generate a fake firewall log with port scanner and SSH brute-force hiden in normal traffic
import random
from datetime import datetime, timedelta 

SCANNER = "203.0.113.50"
BRUTE_FORCER = "198.51.100.23"
NORMAL_USERS = ["192.0.2.10" , "192.0.2.11", "192.0.2.12"]
INTERNAL_HOST = "192.168.1.10"

def make_entry(ts, action, src, port):
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {action} {src} {INTERNAL_HOST} {port} TCP"

def main():
    ts = datetime(2026, 10, 23, 8, 0, 0)
    lines = []
    for _ in range(200):
        ts += timedelta(seconds=random.randint(1, 30))
        roll = random.random()
        if roll < 0.15:
            lines.append(make_entry(ts, "DENY", SCANNER, random.randint(1, 1024)))
        elif roll < 0.30:
            lines.append(make_entry(ts, "DENY", BRUTE_FORCER, 22))
        else:
            lines.append(make_entry(ts, "ALLOW", random.choice(NORMAL_USERS), random.choice([80, 443])))

    with open("firewall.log", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} log entries to firewall.log")

if __name__ == "__main__":
    main()
