from datetime import datetime

# Step 1: Open and read the traffic log
with open("network_traffic.log") as log_file:
    lines = log_file.readlines()

# Step 2: Parse each line and count (source -> destination:port) pairs
pair_counts = {}
pair_times = {}

for line in lines:
    parts = line.split()
    time = parts[0]
    source = parts[1]
    destination = parts[3]  # IP:port after "->"
    pair = f"{source} -> {destination}"

    pair_counts[pair] = pair_counts.get(pair, 0) + 1
    pair_times.setdefault(pair, []).append(time)

# Step 3: Find the pair with the most connections
top_pair = max(pair_counts, key=pair_counts.get)
top_count = pair_counts[top_pair]

# Average seconds between consecutive connections for the top pair
timestamps = [datetime.strptime(t, "%H:%M:%S") for t in pair_times[top_pair]]
intervals = [
    (timestamps[i + 1] - timestamps[i]).total_seconds()
    for i in range(len(timestamps) - 1)
]
avg_seconds = sum(intervals) / len(intervals) if intervals else 0

# Step 4: Print the beaconing suspect report
print("=== Beaconing Suspect ===")
print(f"Pair: {top_pair}")
print(f"Connections: {top_count}")
print(f"Average seconds between connections: {avg_seconds:.0f}")
print("Timestamps:")
for time in pair_times[top_pair]:
    print(f"  {time}")
