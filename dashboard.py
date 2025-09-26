import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="Promon Insight – SOC Demo", layout="wide")

@st.cache_data
def load_data():
    df = pd.read_csv("insights_events.csv", parse_dates=["timestamp"])
    df["date"] = df["timestamp"].dt.date
    return df

df = load_data()

st.title("Promon Insight - MOCK SOC Dashboard")

with st.expander("What is this dashboard?", expanded=True):
    st.markdown(
        """
        This mock dashboard demonstrates how Promon Insight–style telemetry can be used by a SOC
        to triage mobile threat signals quickly. It summarizes events, trends, and simple alert rules.

        Events shown:
        - `root_detected`: Device appears rooted/jailbroken
        - `emulator_detected`: App is running in an emulator/sandbox
        - `hooking_attempt`: Potential runtime hooking or instrumentation (e.g., Frida)
        - `debugger_attached`: Debugger detected during runtime

        Severity:
        - `high`: Requires immediate attention (e.g., emulator on production app, confirmed root)
        - `medium`: Suspicious but may be contextual/benign; review in combination with other signals
        """
    )

# --- Sidebar: global filters ---
with st.sidebar:
    st.header("Filters")
    min_date = df["date"].min()
    max_date = df["date"].max()
    date_range = st.date_input("Date range", value=(min_date, max_date))

    event_sel = st.multiselect("Event type", sorted(df["event"].unique()))
    country_sel = st.multiselect("Country", sorted(df["country"].unique()))
    sev_sel = st.multiselect("Severity", sorted(df["severity"].unique()))

    # Optional per-app filters (shown only if columns exist)
    optional_filters = {}
    for col, label in [
        ("package", "App package"),
        ("app_version", "App version"),
        ("build_number", "Build number"),
        ("environment", "Environment"),
        ("session_id", "Session ID"),
    ]:
        if col in df.columns:
            vals = sorted([v for v in df[col].dropna().unique()])
            if vals:
                optional_filters[col] = st.multiselect(label, vals)

# Apply global filters
filtered = df.copy()
if isinstance(date_range, tuple) and len(date_range) == 2:
    start, end = date_range
    filtered = filtered[(filtered["date"] >= start) & (filtered["date"] <= end)]
if event_sel:
    filtered = filtered[filtered["event"].isin(event_sel)]
if country_sel:
    filtered = filtered[filtered["country"].isin(country_sel)]
if sev_sel:
    filtered = filtered[filtered["severity"].isin(sev_sel)]
# Apply optional filters if present
for col, selected in (optional_filters.items() if 'optional_filters' in locals() else []):
    if selected:
        filtered = filtered[filtered[col].isin(selected)]

# KPI row (from filtered)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", f"{len(filtered):,}")
col2.metric("High Severity", f"{(filtered['severity']=='high').sum():,}")
col3.metric("Unique Devices", f"{filtered['device'].nunique():,}")
col4.metric("Countries", f"{filtered['country'].nunique():,}")

# Charts
c1, c2 = st.columns(2)
with c1:
    st.subheader("Top Attack Types")
    vc_event = filtered["event"].value_counts().sort_values(ascending=False)
    st.bar_chart(vc_event)

with c2:
    st.subheader("Events by Country")
    vc_country = filtered["country"].value_counts().sort_values(ascending=False)
    st.bar_chart(vc_country)

# Choropleth map by country (Plotly)
if not filtered.empty and "country" in filtered.columns:
    st.subheader("Geo Distribution")
    geo_counts = filtered.groupby("country").size().reset_index(name="events")
    fig = px.choropleth(
        geo_counts,
        locations="country",
        locationmode="country names",
        color="events",
        color_continuous_scale="YlOrRd",
        labels={"events": "Events"},
    )
    fig.update_layout(margin=dict(l=0, r=0, t=0, b=0))
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Threats Over Time")
# Group by date and event for a multi-series line
if not filtered.empty:
    ts = (
        filtered.groupby(["date", "event"]).size().unstack(fill_value=0).sort_index()
    )
    st.line_chart(ts)
else:
    st.info("No data for the selected filters.")

st.divider()

# Session drill-down by device
st.subheader("Session Drill-down by Device")
if not filtered.empty:
    device_options = sorted(filtered["device"].dropna().unique())
    sel_device = st.selectbox("Choose a device", options=device_options)
    dev_df = filtered[filtered["device"] == sel_device].sort_values("timestamp")
    st.caption(f"{len(dev_df)} events for: {sel_device}")
    if not dev_df.empty:
        # Timeline scatter by event category
        fig_dev = px.scatter(
            dev_df,
            x="timestamp",
            y="event",
            color="severity",
            hover_data=["country", "device"],
            title=None,
        )
        fig_dev.update_traces(marker=dict(size=10, opacity=0.8))
        fig_dev.update_layout(margin=dict(l=0, r=0, t=0, b=0), yaxis_title="Event")
        st.plotly_chart(fig_dev, use_container_width=True)
        st.dataframe(dev_df, use_container_width=True)
    else:
        st.info("No events for the selected device.")
else:
    st.info("No data to drill down.")

# Raw Events with download
st.divider()
st.subheader("Raw Events")
st.dataframe(filtered.sort_values("timestamp"), use_container_width=True)

csv = filtered.sort_values("timestamp").to_csv(index=False).encode("utf-8")
st.download_button(
    label="Download filtered CSV",
    data=csv,
    file_name="filtered_events.csv",
    mime="text/csv",
)

# --- Alert rule (demo) ---
st.divider()
st.subheader("Alert Rules (demo)")

window_min = st.slider("Rolling window (minutes)", 1, 30, 5)
threshold = st.number_input("Threshold (events in window)", min_value=1, value=10)
scope = st.radio("Scope", ["Per country", "Per device"], horizontal=True)

# Use filtered data but focus on emulator events as before
base = filtered[filtered["event"] == "emulator_detected"].copy()
if base.empty:
    st.info("No emulator_detected events in the current filtered dataset.")
else:
    base = base.sort_values("timestamp").set_index("timestamp")
    group_key = "country" if scope == "Per country" else "device"

    alerts = []
    for key, g in base.groupby(group_key):
        counts = g["event"].rolling(f"{window_min}min").count()
        hits = counts[counts >= threshold]
        for t in hits.index:
            alerts.append({
                "time": t,
                "scope": group_key,
                group_key: key,
                "rule": f"Emulator≥{threshold} in {window_min} min",
            })
    if alerts:
        st.error(f"ALERTS TRIGGERED: {len(alerts)}")
        st.dataframe(pd.DataFrame(alerts).sort_values("time"), use_container_width=True)
    else:
        st.success("No alerts triggered with current rule.")
