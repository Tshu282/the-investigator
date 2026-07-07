from datetime import datetime

LOG_FILES = ["auth_events.log", "file_events.log"]
KEY_MARKERS = ("SUCCESS LOGIN", ".locked", "READ_ME")

# Step 1: Read all lines from both log files
events = []
for log_file in LOG_FILES:
    with open(log_file) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(line)

# Step 2: Parse the date/time at the start of each line for sorting
def event_timestamp(line):
    date_time = line[:19]  # "2026-05-02 01:14:07"
    return datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")

# Step 3: Sort all events in chronological order
events.sort(key=event_timestamp)

# Step 4: Print the merged timeline, flagging key events
print("=== Incident Timeline ===")
for event in events:
    line = event
    if any(marker in event for marker in KEY_MARKERS):
        line += " *** KEY EVENT ***"
    print(line)

# Step 5: Calculate dwell time from first SUCCESS LOGIN to first .locked rename
first_login = None
first_locked = None
for event in events:
    if first_login is None and "SUCCESS LOGIN" in event:
        first_login = event_timestamp(event)
    if first_locked is None and ".locked" in event:
        first_locked = event_timestamp(event)

if first_login and first_locked:
    dwell = first_locked - first_login
    total_seconds = int(dwell.total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    print()
    print("=== Dwell Time ===")
    print(f"From: {first_login.strftime('%Y-%m-%d %H:%M:%S')} (first SUCCESS LOGIN)")
    print(f"To:   {first_locked.strftime('%Y-%m-%d %H:%M:%S')} (first .locked rename)")
    print(f"Dwell time: {minutes} minutes {seconds} seconds ({total_seconds} seconds)")
