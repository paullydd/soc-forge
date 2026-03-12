import csv
import json
from pathlib import Path

INPUT = Path("security_events.csv")
OUTPUT = Path("security_events.jsonl")

def parse_message_fields(message: str) -> dict:
    msg = message or ""
    details = {}

    # very lightweight extraction helpers
    if "Account Name:" in msg:
        parts = msg.split("Account Name:")
        if len(parts) > 1:
            val = parts[1].splitlines()[0].strip()
            if val and val not in {"-", "SYSTEM"}:
                details.setdefault("username", val)
                details.setdefault("target_user", val)

    if "Target Account Name:" in msg:
        parts = msg.split("Target Account Name:")
        if len(parts) > 1:
            val = parts[1].splitlines()[0].strip()
            if val:
                details["target_user"] = val

    if "Group Name:" in msg:
        parts = msg.split("Group Name:")
        if len(parts) > 1:
            val = parts[1].splitlines()[0].strip()
            if val:
                details["group_name"] = val

    return details

with INPUT.open("r", encoding="utf-8-sig", newline="") as f_in, OUTPUT.open("w", encoding="utf-8") as f_out:
    reader = csv.DictReader(f_in)
    for row in reader:
        message = row.get("Message", "") or ""
        event = {
            "timestamp": row.get("TimeCreated", ""),
            "event_id": int(row.get("Id", 0) or 0),
            "message": message,
            "host": "WINDOWS-PC",
        }
        event.update(parse_message_fields(message))
        f_out.write(json.dumps(event) + "\n")

print(f"Wrote {OUTPUT}")
