# Promon Insight™ Telemetry Dashboard (Mock)

**Live demo:** https://promon-insights-dashboard-demo.streamlit.app/

A small prototype that turns **Promon Insight–style telemetry** (root/emulator/hook/debug) into **SOC-ready** KPIs, trends, and alert rules.  
Uses **mock, non-PII** data to demonstrate how customers (e.g., banks/ID apps) could triage threats fast.

---

## Features

- **KPI cards:** Total events, high-severity count, unique devices, countries
- **Top attack types:** Bar chart of `root_detected`, `emulator_detected`, `hooking_attempt`, `debugger_attached`
- **By country:** Quick geo distribution (bar)
- **Threats over time:** Daily line chart
- **Filters:** By event / country / severity
- **Alert rule (demo):** “≥ *N* emulator events in *W* minutes” (rolling window).  
  – Scope defaults to **per country**; switch to **per device/IP** for tighter noise control.

---

## Data (mock)

- File: `insights_events.csv`  
- Columns:
  - `timestamp` (ISO8601)
  - `event` (`root_detected`, `emulator_detected`, `hooking_attempt`, `debugger_attached`)
  - `severity` (`high`/`medium`)
  - `device` (e.g., “Android 14 Samsung S22”)
  - `country` (e.g., “Norway”)

> This repo and demo use **synthetic data only**.

---

## How to run locally

1. Create a virtual environment (optional but recommended)
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Start the app
   ```bash
   streamlit run dashboard.py
   ```
4. Open the URL printed in the terminal (usually `http://localhost:8501`).
