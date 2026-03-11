import os
import pandas as pd
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8001")

st.set_page_config(
    page_title="ThreatLens XDR Lab",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ThreatLens XDR Lab")
st.caption("Endpoint Threat Research, SIEM Analytics, and Detection Prototype")


def get_json(path: str):
    response = requests.get(f"{API_BASE_URL}{path}", timeout=15)
    response.raise_for_status()
    return response.json()


def post_json(path: str):
    response = requests.post(f"{API_BASE_URL}{path}", timeout=30)
    response.raise_for_status()
    return response.json()


try:
    health = get_json("/health")
    stats = get_json("/stats")
    alerts = get_json("/alerts")
except Exception as e:
    st.error(f"Could not reach API: {e}")
    st.stop()

top1, top2, top3, top4 = st.columns(4)
top1.metric("Linux Events", stats.get("linux_events", 0))
top2.metric("Windows Events", stats.get("windows_events", 0))
top3.metric("Sandbox Events", stats.get("sandbox_events", 0))
top4.metric("Alerts", stats.get("alerts", 0))

st.subheader("Operations")

c1, c2 = st.columns(2)

with c1:
    if st.button("Ingest All Events"):
        result = post_json("/ingest/all")
        st.success(result)
        st.rerun()

with c2:
    if st.button("Run Detection Engine"):
        result = post_json("/detect")
        st.success(result)
        st.rerun()

st.subheader("Platform Health")
st.json(health)

if isinstance(alerts, list) and alerts:
    df = pd.DataFrame(alerts)

    st.subheader("Recent Alerts")
    preferred_cols = [
        "timestamp",
        "severity",
        "threat_type",
        "source_type",
        "mitre_technique_id",
        "mitre_technique_name",
        "host",
        "source_ip",
        "description",
        "status",
    ]
    existing_cols = [c for c in preferred_cols if c in df.columns]
    st.dataframe(df[existing_cols], use_container_width=True)

    chart1, chart2 = st.columns(2)

    with chart1:
        st.subheader("Alerts by Severity")
        if "severity" in df.columns:
            severity_counts = df["severity"].value_counts()
            st.bar_chart(severity_counts)

    with chart2:
        st.subheader("Alerts by MITRE Technique")
        if "mitre_technique_id" in df.columns:
            mitre_counts = (
                df["mitre_technique_id"]
                .fillna("unknown")
                .value_counts()
            )
            st.bar_chart(mitre_counts)

    st.subheader("Alerts by Source Type")
    if "source_type" in df.columns:
        source_counts = df["source_type"].value_counts()
        st.bar_chart(source_counts)

else:
    st.info("No alerts yet. Ingest events and run the detection engine.")

st.subheader("Research Coverage")
st.markdown("""
- Linux security event ingestion
- Windows endpoint threat simulation
- Malware sandbox behaviour events
- Elasticsearch indexing
- MITRE ATT&CK-mapped detections
- API-driven detection workflow
- Analyst-focused dashboard
- Dockerised multi-service setup
""")