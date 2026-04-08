import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import sqlite3

conn = sqlite3.connect("cyber_login.db")
df = pd.read_sql_query("SELECT * FROM login_data", conn)

st.set_page_config(page_title="Cyber Threat Detection System", layout="wide")

st.title(" Cyber Threat Detection System")
st.write("Detects suspicious login activity, high-risk IPs, and potential attacks.")
st.title("Cyber Threat Detection & Investigation System")

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

failed_df = df[df["login_status"] == "failure"]

total_logins = len(df)
total_failures = len(failed_df)

ip_failures = failed_df.groupby("ip_address")["failed_attempts"].sum().reset_index()
user_failures = failed_df.groupby("user_id")["failed_attempts"].sum().reset_index()

high_risk_ips = ip_failures[ip_failures["failed_attempts"] >= 5]
high_risk_users = user_failures[user_failures["failed_attempts"] >= 5]

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Logins", total_logins)
col2.metric("Failed Logins", total_failures)
col3.metric("High Risk IPs", len(high_risk_ips))
col4.metric("High Risk Users", len(high_risk_users))

ip_failures["risk_level"] = ip_failures["failed_attempts"].apply(
    lambda x: "High" if x >= 5 else "Medium" if x >= 3 else "Low"
)
user_failures["risk_level"] = user_failures["failed_attempts"].apply(
    lambda x: "High" if x >= 5 else "Medium" if x >= 3 else "Low"
)
st.divider()
st.subheader("Alerts")

for _, row in high_risk_ips.iterrows():
    st.error(f"Possible brute force attack from IP {row['ip_address']} ({row['failed_attempts']} failures)")

for _, row in high_risk_users.iterrows():
    st.warning(f"User {row['user_id']} has multiple failed login attempts ({row['failed_attempts']})")
# Unusual login time alerts
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
st.subheader("Full Failed Login Records")
st.dataframe(df[["user_id", "ip_address", "failed_attempts", "hour", "risk_score", "risk_level"]])
st.divider()
st.subheader("Investigation Panel")

search_value = st.text_input("Enter User ID or IP Address")

if search_value:
    results = df[
        (df["user_id"] == search_value) |
        (df["ip_address"] == search_value)
    ]

    if not results.empty:
        st.write("### Matching Records")
        st.dataframe(results)

        st.write("### Summary")
        st.write(f"Total Records: {len(results)}")
        st.write(f"Total Failures: {results['failed_attempts'].sum()}")
        st.write(f"Average Risk Score: {results['risk_score'].mean():.2f}")
    else:
        st.warning("No records found")

st.divider()
st.subheader("Incident Tracker")

incident_tracker = incident_df.copy()
incident_tracker["Status"] = "Open"
incident_tracker["Assigned To"] = "Analyst 1"

st.dataframe(incident_tracker, use_container_width=True)
conn.close()