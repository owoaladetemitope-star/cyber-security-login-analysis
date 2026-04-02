import pandas as pd

df = pd.read_csv(
    r"C:\Users\bowoalade\Documents\cyber_projrct\data\login_data.csv",
    sep=","
)

print(df.head())
print(df.columns)