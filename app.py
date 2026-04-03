import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

st.set_page_config(page_title="Cyber Login Risk Dashboard", layout="wide")

st.title("Cybersecurity Login Threat Detection Dashboard")
st.write("This dashboard analyzes login activity to identify suspicious IP addresses, risky users, and failed login patterns.")

# load data
df = pd.read_csv("data/login_data.csv")

# clean columns
df["login_status"] = df["login_status"].str.strip().str.lower()
df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour

# failed logins only
failed_df = df[df["login_status"] == "failure"]

# top suspicious IPs
ip_failures = failed_df.groupby("ip_address").size().reset_index(name="failed_attempts")
ip_failures = ip_failures.sort_values(by="failed_attempts", ascending=False)

# add IP risk level
ip_failures["risk_level"] = ip_failures["failed_attempts"].apply(
    lambda x: "High Risk" if x >= 5 else "Medium Risk" if x >= 3 else "Low Risk"
)

# top suspicious users
user_failures = failed_df.groupby("user_id").size().reset_index(name="failed_attempts")
user_failures = user_failures.sort_values(by="failed_attempts", ascending=False)

# add user risk level
user_failures["risk_level"] = user_failures["failed_attempts"].apply(
    lambda x: "High Risk" if x >= 5 else "Medium Risk" if x >= 3 else "Low Risk"
)

# failed logins by hour
hourly_failures = failed_df.groupby("hour").size().reset_index(name="failed_attempts")
hourly_failures = hourly_failures.sort_values(by="hour")

# layout
col1, col2 = st.columns(2)

with col1:
    st.subheader("Top Suspicious IP Addresses")
    st.caption("IP addresses with the highest number of failed login attempts.")
    st.dataframe(ip_failures.head(10), use_container_width=True)

with col2:
    st.subheader("Top Suspicious Users")
    st.caption("Users with repeated failed login attempts.")
    st.dataframe(user_failures.head(10), use_container_width=True)

st.subheader("Failed Logins by Hour")

fig, ax = plt.subplots()
ax.bar(hourly_failures["hour"], hourly_failures["failed_attempts"])
ax.set_title("Failed Logins by Hour")
ax.set_xlabel("Hour of Day")
ax.set_ylabel("Number of Failed Attempts")
st.pyplot(fig)

st.subheader("Full Failed Login Records")
st.dataframe(failed_df, use_container_width=True)