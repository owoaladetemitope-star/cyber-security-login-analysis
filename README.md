# Cyber Threat Detection & Investigation System

## Overview
This project simulates a realworld Security Operations Center (SOC) system that monitors authentication logs to detect potential cyber threats. The system analyzes login activity, detects suspicious behavior, assigns dynamic risk scores, and provides an interactive dashboard for investigation and incident tracking. It is designed to reflect how cybersecurity analysts detect and respond to threats in real environments.

## Key Features
- Detects brute force attacks using repeated failed login attempts
- Identifies high-risk users and suspicious IP addresses
- Implements behavior-based threat detection (unusual login times)
- Calculates dynamic risk scores (0–100)
- Uses AI-based anomaly detection with Isolation Forest
- Assigns automatic risk levels (Low, Medium, High)
- Generates real-time security alerts
- Performs IP reputation checking
- Detects login source countries using IP geolocation
- Maps threats to MITRE ATT&CK techniques
- Provides a threat hunting investigation panel for user/IP analysis
- Includes incident tracking with status updates and analyst assignment
- Logs security events in SIEM-style JSON format
- Includes a SIEM Event Viewer dashboard
- Visualizes attack patterns and threat metrics

## System Workflow
1. Login data is loaded into a SQLite database
2. Authentication logs are processed using Python
3. Rule-based threat detection identifies suspicious activity
4. Behavioral analysis detects unusual login patterns
5. Isolation Forest detects anomalies
6. Risk scores are calculated dynamically
7. Security alerts are generated
8. Events are logged in SIEM-style JSON format
9. Analysts investigate users or IPs through the dashboard
10. Incidents are tracked through response workflows

## AI Integration
This system includes an anomaly detection model using Isolation Forest, an unsupervised machine learning algorithm that identifies unusual login behavior based on patterns in the data. This enhances detection beyond rule-based methods by flagging previously unseen attack patterns.

## Technologies Used
- Python
- Pandas
- Streamlit
- SQLite
- Scikit-learn
- Matplotlib
- Requests API
- JSON logging
- MITRE ATT&CK framework concepts 

## Example Use Cases
- Detecting brute force login attacks
- Threat hunting suspicious users or IP addresses
- Investigating abnormal authentication activity
- Monitoring security alerts
- Tracking incidents through analyst workflows
- Reviewing SIEM-style security logs

## How to Run
Install dependencies:
pip install streamlit pandas matplotlib scikit-learn requests
Run the application:
python -m streamlit run app.py

## Future Improvements
- Real-time log ingestion
- Integration with external threat intelligence APIs
- Cloud deployment (AWS / Azure)
- Email alert notifications
- User authentication and analyst roles
- Persistent incident management database 

## Purpose
This project demonstrates practical skills used in cybersecurity and data roles, including:
- Security monitoring
- Threat detection
- Threat hunting
- Incident response workflows
- Log analysis
- SIEM concepts
- MITRE ATT&CK mapping
- Behavioral analytics
- Machine learning for cybersecurity
- SQL data handling
- Dashboard development  
This system is designed to simulate real SOC analyst workflows and demonstrate the ability to build data driven security solutions.
