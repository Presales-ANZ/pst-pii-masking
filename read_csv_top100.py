import pandas as pd

# Read the CSV file
csv_file = "your_file.csv"  # Replace with your CSV file path
df = pd.read_csv(csv_file)

# Display the top 100 rows
print(df.head(100))
