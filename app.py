import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import sqlite3

conn = sqlite3.connect("cyber_login.db")
df = pd.read_sql_query("SELECT * FROM login_data", conn)

st.set_page_config(page_title="Cyber Threat Detection System", layout="wide")

st.title("🚨 Cyber Threat Detection System")
st.write("Detects suspicious login activity, high-risk IPs, and potential attacks.")

df["failed_attempts"] = pd.to_numeric(df["failed_attempts"], errors="coerce")

df["login_status"] = df["login_status"].str.strip().str.lower()
df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour

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

st.subheader("🚨 Alerts")

for _, row in high_risk_ips.iterrows():
    st.error(f"Possible brute force attack from IP {row['ip_address']} ({row['failed_attempts']} failures)")

for _, row in high_risk_users.iterrows():
    st.warning(f"User {row['user_id']} has multiple failed login attempts ({row['failed_attempts']})")

st.subheader("📊 Detected Incidents")

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
st.dataframe(failed_df)
conn.close()