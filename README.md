# Cyber Threat Detection System

## Overview
This project is a cybersecurity analytics system designed to detect suspicious login behavior, identify potential brute force attacks, and highlight highrisk users and IP addresses.
It simulates how real world security teams monitor login activity and respond to potential threats using data analysis and visualization.

## 🔍 Key Features

* Detects repeated failed login attempts (brute force patterns)
* Identifies highrisk IP addresses and users
* Assigns risk levels (Low, Medium, High) based on behavior
* Analyzes attack patterns by time (hourly trends)
* Generates real time alerts for suspicious activity
* Displays findings in an interactive dashboard

## Technologies/Tools Used

* **Python** (pandas, matplotlib)
* **SQL (SQLite)** for data storage
* **Streamlit** for building the dashboard
* Data analysis and anomaly detection techniques

## How It Works

1. Login data is loaded from a CSV file into a SQL database
2. The system analyzes login activity using Python
3. Failed login attempts are tracked and grouped
4. Suspicious behavior is identified based on thresholds and patterns
5. Results are displayed in a dashboard with alerts and visualizations

## Example Insights

* IP addresses with repeated failed login attempts are flagged as high risk
* Users with multiple login failures are identified for further investigation
* Attack activity is analyzed by hour to detect unusual patterns

## 🚀 How to Run

Install dependencies:

pip install streamlit pandas matplotlib

Run the application:

streamlit run app.py

## 💡 Future Improvements

* Real time log streaming instead of static data
* Integration with external threat intelligence (IP reputation APIs)
* Machine learning for anomaly detection
* Deployment to cloud (AWS / Azure)

## 🎯 Purpose

This project demonstrates practical cybersecurity skills including:

* Threat detection
* Data analysis
* SQL database usage
* Dashboard development

It is designed to simulate real world security monitoring systems used by analysts in Security Operations Centers (SOC).
