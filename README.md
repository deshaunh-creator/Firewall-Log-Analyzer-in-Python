# Firewall-Log-Analyzer-in-Python
Python tool I built while studying cybersecurity. Reads a simulated firewall log, flags IPs that look like port scans (10+ denied ports) or SSH/RDP brute force (5+ denied logins), and writes them to a block list. Thresholds are adjustable. Includes a script that generates the fake log data.

# Firewall Log Analyzer

## What it does

It looks for two behaviors:

- Port scanning: one IP getting denied on 10 or more different ports
- Brute force: 5 or more denied attempts on SSH (22) or RDP (3389) from one IP

Flagged IPs are printed to the terminal and saved to blocklist.txt, one per line.

## How to run

You only need Python 3.

python3 generatelogs.py
python3 analyzelog.py

Run both from the same folder. The first script creates a fake firewall.log with a scanner and a brute forcer hidden in normal traffic. The second reads it and prints what it found.

## How the code works

parse_line()
Each log line is split into 7 fields (date, time, action, source IP, destination IP, port, protocol) and turned into a dictionary. Lines that are malformed get skipped so one bad entry doesn't crash the script.

analyze()
Reads the log and ignores anything that isn't a DENY, since blocked traffic is what's worth investigating. For every denied connection it does two things:

1. Adds the port to a set for that source IP. A set only keeps unique values, so its length is the number of different ports that IP tried.
2. If the port is 22 or 3389, adds 1 to a counter for that IP.

After reading the whole log, it checks each IP against the thresholds. Many different ports means a scan (breadth). Many attempts on a login port means brute force (depth). An IP already flagged as a scanner isn't flagged twice.

main()
Runs the analysis, prints the results, and writes the IPs to blocklist.txt.

## Adjusting detection

The thresholds are constants at the top of analyzelog.py:

SCAN_PORT_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 5
LOGIN_PORTS = {22, 3389}

Lower values catch more but cause more false positives. Higher values miss slower attacks. Changing them and rerunning shows the tradeoff.

## Limitations

- The data is simulated
- It counts totals across the whole log, with no time windows
- It only checks denied traffic and a short list of login ports

## What I want to add next

- Time windows, like 10 ports in 60 seconds
- Testing on real sample firewall logs
- Detection for one IP hitting many internal hosts
