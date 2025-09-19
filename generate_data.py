import pandas as pd
import random
from datetime import datetime, timedelta

random.seed(42)

EVENTS = ["root_detected", "emulator_detected", "hooking_attempt", "debugger_attached"]
DEVICES = ["Android 14 Samsung S22", "iOS 17 iPhone 13", "Android 13 Pixel 6", "iOS 16 iPhone 11"]
COUNTRIES = ["Norway", "Sweden", "Germany", "UK", "USA"]

start = datetime(2025, 9, 1, 8, 0, 0)
rows = []
for i in range(200):
    ts = start + timedelta(minutes=random.randint(0, 60*24*20)) #2 weeks
    event = random.choice(EVENTS)
    severity = "high" if event in ["root_detected", "hooking_attempt"] else "medium"
    device = random.choice(DEVICES)
    country = random.choice(COUNTRIES)
    rows.append({
        "timestamp": ts.isoformat(timespec="seconds"),
        "event": event,
        "severity": severity,
        "device":device,
        "country":country
    })

df = pd.DataFrame(rows).sort_values("timestamp")
df.to_csv("insights_events.csv", index=False)
print("Wrote insight_events.csv with", len(df), "rows")