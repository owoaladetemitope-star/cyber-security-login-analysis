import pandas as pd
import sqlite3

df = pd.read_csv("data/login_data.csv")

conn = sqlite3.connect("cyber_login.db")

df.to_sql("login_data", conn, if_exists="replace", index=False)

print("Database created successfully: cyber_login.db")

conn.close()