# Cyber Threat Detection & Investigation System

## Overview
This project simulates a realworld Security Operations Center (SOC) system that monitors authentication logs to detect potential cyber threats. The system analyzes login activity, detects suspicious behavior, assigns dynamic risk scores, and provides an interactive dashboard for investigation and incident tracking. It is designed to reflect how cybersecurity analysts detect and respond to threats in real environments.

## Key Features
- Detects brute force attacks using repeated failed login attempts  
- Identifies high-risk users and IP addresses  
- Implements behavior based detection (unusual login times)  
- Calculates dynamic risk scores (0–100) based on multiple factors  
- Assigns risk levels (Low, Medium, High) automatically  
- Generates real time alerts for suspicious activity  
- Provides an investigation panel to analyze user/IP behavior  
- Includes an incident tracking system with status and assignment  
- Visualizes attack patterns and trends 

## System Workflow
1. Login data is loaded into a SQL database  
2. The system processes authentication logs using Python  
3. Behavioral and threshold based detection logic is applied  
4. Each record is assigned a risk score and classification  
5. Alerts are generated for suspicious activity  
6. Analysts can investigate entities using the dashboard  
7. Incidents are tracked and monitored

## Technologies Used
- Python (pandas, matplotlib)  
- SQLite (data storage and querying)  
- Streamlit (interactive dashboard)  
- Data analysis and anomaly detection techniques 

## Example Use Cases
- Detecting brute force login attempts  
- Identifying compromised accounts  
- Investigating suspicious login behavior  
- Monitoring attack patterns over time  
- Supporting security decision-making with data

## How to Run
Install dependencies:
pip install streamlit pandas matplotlib
Run the application:
python -m streamlit run app.py

## Future Improvements
- Real-time log ingestion instead of static datasets  
- Integration with external threat intelligence APIs  
- Machine learning-based anomaly detection  
- Cloud deployment (AWS / Azure)  
- User authentication and role-based access 

## Purpose
This project demonstrates practical skills used in cybersecurity and data roles, including:
- Security monitoring and threat detection  
- Behavioral analysis and risk scoring  
- SQL data handling  
- Dashboard development and data visualization  
- Investigation and incident response workflows  
This system is designed to simulate real SOC analyst workflows and demonstrate the ability to build data driven security solutions.
