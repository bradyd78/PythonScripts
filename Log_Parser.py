import re

# Regex pattern for IPv4 addresses
ip_pattern = r"\d{1,3}(?:\.\d{1,3}){3}"

# Read the log file
with open("log.txt", "r") as file:
    logs = file.read()

# Find all IP addresses
ips = re.findall(ip_pattern, logs)

# Remove duplicates
unique_ips = set(ips)

print("Found ip addresses: ")
for ips in unique_ips:
    print(ip)

