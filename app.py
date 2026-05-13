import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import sqlite3
import requests
import json
from sklearn.ensemble import IsolationForest
from event_logger import log_security_event

def check_ip_reputation(ip):
    suspicious_ips = ["8.8.8.8", "45.33.32.1", "203.0.113.5"]

    if ip in suspicious_ips:
        return "Suspicious"
    else:
        return "Clean"
    
def get_mitre_technique(event_type):
    mitre_map = {
        "Brute Force Attack": "T1110 - Brute Force",
        "Suspicious User Activity": "T1078 - Valid Accounts",
        "Unusual Login Time": "T1078 - Valid Accounts"
    }

    return mitre_map.get(event_type, "Unknown Technique")
def lookup_ip_country(ip):
    private_ips = ["192.168", "10.", "172.16"]

    if any(ip.startswith(p) for p in private_ips):
        return "Internal / Trusted"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"

conn = sqlite3.connect("cyber_login.db")
df = pd.read_sql_query("SELECT * FROM login_data", conn)

st.set_page_config(page_title="Cyber Threat Detection System", layout="wide")

st.title("Cyber Threat Detection & Investigation System")
st.write("Detects suspicious login activity, high-risk IPs, and potential attacks.")

st.markdown("""
### Real-Time Security Monitoring Dashboard

This system analyzes login behavior, detects threats, assigns risk scores, and supports investigation workflows.

- Detects brute force attacks  
- Identifies suspicious users and IPs  
- Calculates dynamic risk scores  
- Enables investigation and incident tracking  
""")

df["failed_attempts"] = pd.to_numeric(df["failed_attempts"], errors="coerce")

df["login_status"] = df["login_status"].str.strip().str.lower()
df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
# Detect unusual login hours (outside 6am–10pm)
df["unusual_time"] = df["hour"].apply(lambda x: 1 if x < 6 or x > 22 else 0)
def calculate_risk(row):
    score = 0
    score += row["failed_attempts"] * 5
    if row["unusual_time"] == 1:
        score += 20
    return min(score, 100)
df["risk_score"] = df.apply(calculate_risk, axis=1)
def get_risk_level(score):
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"
df["risk_level"] = df["risk_score"].apply(get_risk_level)
# ---------------- AI ANOMALY DETECTION ----------------

df["login_failed"] = (df["login_status"] == "failure").astype(int)

ai_features = df[["failed_attempts", "hour", "login_failed"]].copy()

model = IsolationForest(contamination=0.15, random_state=42)
df["anomaly"] = model.fit_predict(ai_features)

df["anomaly_label"] = df["anomaly"].apply(
    lambda x: "Suspicious" if x == -1 else "Normal"
)

anomaly_df = df[df["anomaly"] == -1]

failed_df = df[df["login_status"] == "failure"]

total_logins = len(df)
total_failures = len(failed_df)

ip_failures = failed_df.groupby("ip_address")["failed_attempts"].sum().reset_index()
user_failures = failed_df.groupby("user_id")["failed_attempts"].sum().reset_index()

high_risk_ips = ip_failures[ip_failures["failed_attempts"] >= 5]
high_risk_users = user_failures[user_failures["failed_attempts"] >= 5]

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Logins", total_logins)
col2.metric("Failed Logins", total_failures)
col3.metric("High Risk IPs", len(high_risk_ips))
col4.metric("High Risk Users", len(high_risk_users))
col5.metric("AI Anomalies", len(anomaly_df))

ip_failures["risk_level"] = ip_failures["failed_attempts"].apply(
    lambda x: "High" if x >= 5 else "Medium" if x >= 3 else "Low"
)
user_failures["risk_level"] = user_failures["failed_attempts"].apply(
    lambda x: "High" if x >= 5 else "Medium" if x >= 3 else "Low"
)
st.divider()
st.subheader("Alerts")

for _, row in high_risk_ips.iterrows():
    reputation = check_ip_reputation(row["ip_address"])
    mitre = get_mitre_technique("Brute Force Attack")
    country = lookup_ip_country(row["ip_address"])

    st.error(
    f"Possible brute force attack from IP {row['ip_address']} "
    f"({row['failed_attempts']} failures) | Country: {country} | Reputation: {reputation} | MITRE: {mitre}"
)

    log_security_event(
        event_type="Brute Force Attack",
        source_ip=row["ip_address"],
        user="Unknown",
        severity="High"
    )

for _, row in high_risk_users.iterrows():
    mitre = get_mitre_technique("Suspicious User Activity")

    st.warning(
        f"User {row['user_id']} has multiple failed login attempts "
        f"({row['failed_attempts']}) | MITRE: {mitre}"
    )

    log_security_event(
        event_type="Suspicious User Activity",
        source_ip="Unknown",
        user=row["user_id"],
        severity="Medium"
    )
unusual_logins = df[df["unusual_time"] == 1]
for _, row in unusual_logins.iterrows():
    st.warning(f"Unusual login time detected for user {row['user_id']} at hour {row['hour']}")

st.divider()
st.subheader("Detected Incidents")

incidents = []

for _, row in high_risk_ips.iterrows():
    incidents.append({
        "Type": "Brute Force IP",
        "Source": row["ip_address"],
        "Attempts": row["failed_attempts"],
        "Risk": "High"
    })

for _, row in high_risk_users.iterrows():
    incidents.append({
        "Type": "Suspicious User",
        "Source": row["user_id"],
        "Attempts": row["failed_attempts"],
        "Risk": "High"
    })

incident_df = pd.DataFrame(incidents)

st.dataframe(incident_df, use_container_width=True)

col1, col2 = st.columns(2)

with col1:
    st.subheader("Top Suspicious IPs")
    st.dataframe(ip_failures.sort_values(by="failed_attempts", ascending=False).head(10))

with col2:
    st.subheader("Top Suspicious Users")
    st.dataframe(user_failures.sort_values(by="failed_attempts", ascending=False).head(10))

st.subheader("Failed Logins by Hour")

hourly_failures = failed_df.groupby("hour").size().reset_index(name="failed_attempts")

fig, ax = plt.subplots()
ax.bar(hourly_failures["hour"], hourly_failures["failed_attempts"])
ax.set_xlabel("Hour")
ax.set_ylabel("Failures")
ax.set_title("Attack Timing Pattern")

st.pyplot(fig)
st.divider()
st.subheader("AI Detected Suspicious Logins")

st.dataframe(
    anomaly_df[
        [
            "user_id",
            "timestamp",
            "ip_address",
            "failed_attempts",
            "hour",
            "risk_score",
            "anomaly_label",
        ]
    ],
    use_container_width=True
)
st.subheader("Full Failed Login Records")
st.dataframe(df[["user_id", "ip_address", "failed_attempts", "hour", "risk_score", "risk_level"]])
st.divider()
st.subheader("Investigation Panel")

search_term = st.text_input("Enter User ID or IP Address")

if search_term:
    results = df[
        (df["user_id"].astype(str).str.contains(search_term, case=False)) |
        (df["ip_address"].astype(str).str.contains(search_term, case=False))
    ]

    if not results.empty:
        st.success(f"Found {len(results)} matching records")
        st.dataframe(results, use_container_width=True)

        st.write("### Threat Hunt Summary")
        st.write(f"Total Matches: {len(results)}")
        st.write(f"Total Failed Attempts: {results['failed_attempts'].sum()}")
        st.write(f"Highest Risk Score: {results['risk_score'].max()}")
    else:
        st.warning("No matching records found")

st.divider()
st.subheader("Incident Tracker")
incident_status = st.selectbox(
    "Update Incident Status",
    ["Open", "Investigating", "Escalated", "Resolved"]
)

assigned_analyst = st.selectbox(
    "Assign Analyst",
    ["Analyst 1", "Analyst 2", "Analyst 3"]
)

incident_tracker = pd.DataFrame(incidents)
incident_tracker["Status"] = incident_status
incident_tracker["Assigned To"] = assigned_analyst


st.dataframe(incident_tracker, use_container_width=True)
st.divider()
st.subheader("SIEM Event Viewer")

with open("security_events.json", "r") as f:
    logs = [json.loads(line) for line in f]

logs_df = pd.DataFrame(logs)

st.dataframe(logs_df, use_container_width=True)
conn.close()