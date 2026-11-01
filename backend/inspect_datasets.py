import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

files = [
    "phishtank.csv",
    "phishunt.csv",
    "tranco.csv"
]

for filename in files:

    path = DATA_DIR / filename

    print("\n" + "=" * 50)
    print("FILE:", filename)
    print("=" * 50)

    if not path.exists():
        print("File not found!")
        continue

    try:
        df = pd.read_csv(path, encoding="utf-8", nrows=5)

        print("\nColumns:")
        print(df.columns.tolist())

        print("\nFirst 5 rows:")
        print(df.to_string(index=False))

    except Exception as error:
        print("Error:", error)