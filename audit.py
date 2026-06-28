# Step 1: Open and read the log file
with open("server_access.log") as log_file:
    lines = log_file.readlines()

# Step 2 & 3: Find FAILED LOGIN lines and extract IP addresses
ip_counts = {}

for line in lines:
    if "FAILED LOGIN" not in line:
        continue

    # IP appears after "from " (may be followed by extra text like "(Moscow)")
    ip = line.split("from ")[1].split()[0]
    ip_counts[ip] = ip_counts.get(ip, 0) + 1

# Step 4 & 5: Print summary sorted by most attempts first
print("=== Failed Login Summary ===")
for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
    line = f"{ip}: {count} failed attempt(s)"
    # Flag IPs with 3+ failures as likely brute force
    if count >= 3:
        line += " ⚠️ LIKELY BRUTE FORCE"
    print(line)
