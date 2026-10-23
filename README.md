# Firewall-Log-Analyzer-in-Python
Python tool I built while studying cybersecurity. Reads a simulated firewall log, flags IPs that look like port scans (10+ denied ports) or SSH/RDP brute force (5+ denied logins), and writes them to a block list. Thresholds are adjustable. Includes a script that generates the fake log data.
