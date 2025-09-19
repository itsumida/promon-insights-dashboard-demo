import pandas as pd
import streamlit as st

st.set_page_config(page_title="Promon Insight – SOC Demo", layout="wide")

@st.cache_data
def load_data():
    df = pd.read_csv("insights_events.csv", parse_dates=["timestamp"])
    df["date"] = df["timestamp"].dt.date
    return df

df = load_data()

st.title("Promon Insight - MOCK SOC Dashboard")

# KPI row
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", f"{len(df):,}")
col2.metric("High Severity", f"{(df['severity']=='high').sum():,}")
col3.metric("Unique Devices", f"{df['device'].nunique():,}")
col4.metric("Countries", f"{df['country'].nunique():,}")

# Charts
c1, c2 = st.columns(2)
with c1:
    st.subheader("Top Attack Types")
    st.bar_chart(df["event"].value_counts())

with c2:
    st.subheader("Events by Country")
    st.bar_chart(df["country"].value_counts())

st.subheader("Threats Over Time (Daily)")
daily = df.groupby("date").size()
st.line_chart(daily)

st.divider()
st.subheader("Raw Events (filterable)")
with st.expander("Filters", expanded=False):
    event_sel = st.multiselect("Event type", sorted(df["event"].unique()))
    country_sel = st.multiselect("Country", sorted(df["country"].unique()))
    sev_sel = st.multiselect("Severity", sorted(df["severity"].unique()))
tmp = df.copy()
if event_sel:   tmp = tmp[tmp["event"].isin(event_sel)]
if country_sel: tmp = tmp[tmp["country"].isin(country_sel)]
if sev_sel:     tmp = tmp[tmp["severity"].isin(sev_sel)]
st.dataframe(tmp.sort_values("timestamp"), use_container_width=True)

# --- Simple alert rule ---
st.divider()
st.subheader("Alert Rules (demo)")

window_min = st.slider("Rolling window (minutes)", 1, 30, 5)
threshold = st.number_input("Threshold (events in window)", min_value=1, value=10)

# Example alert: too many emulator detections in a short window (per country)
df2 = df[df["event"] == "emulator_detected"].copy()
if df2.empty:
    st.info("No emulator_detected events in the dataset.")
else:
    df2 = df2.sort_values("timestamp")
    df2.set_index("timestamp", inplace=True)
    alerts = []
    for country, g in df2.groupby("country"):
        counts = g["event"].rolling(f"{window_min}min").count()
        hits = counts[counts >= threshold]
        for t in hits.index:
            alerts.append({"time": t, "country": country, "rule": f"Emulator≥{threshold} in {window_min} min"})
    if alerts:
        st.error(f"ALERTS TRIGGERED: {len(alerts)}")
        st.dataframe(pd.DataFrame(alerts).sort_values("time"), use_container_width=True)
    else:
        st.success("No alerts triggered with current rule.")
