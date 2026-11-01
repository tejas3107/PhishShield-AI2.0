import pandas as pd
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Extract hostname for overlap checking
def get_domain(url):
    try:
        hostname = urlparse(str(url)).hostname
        return hostname.lower().removeprefix("www.") if hostname else None
    except Exception:
        return None


# 1. Load PhishTank
print("\nLoading PhishTank...")

pt = pd.read_csv(DATA_DIR / "phishtank.csv")

pt = pt[
    pt["verified"].astype(str).str.lower() == "yes"
]

phish1 = pt["url"].dropna()


# 2. Load Phishunt
print("\nLoading Phishunt...")

ph = pd.read_csv(DATA_DIR / "phishunt.csv")

ph = ph[
    ph["verdict"].astype(str).str.lower() == "high"
]

phish2 = ph["url"].dropna()


# 3. Combine phishing URLs
phishing = pd.concat(
    [phish1, phish2],
    ignore_index=True
)

phishing = phishing.drop_duplicates()


# 4. Load Tranco
print("\nLoading Tranco...")

tr = pd.read_csv(
    DATA_DIR / "tranco.csv",
    header=None,
    names=["rank", "domain"]
)

tr = tr.dropna(subset=["domain"]).head(100000)

legitimate = "https://" + tr["domain"].astype(str)


# 5. Remove phishing domain overlaps
print("\nRemoving domain overlaps...")

phishing_domains = set(
    phishing.apply(get_domain).dropna()
)

legitimate_df = pd.DataFrame({
    "url": legitimate
})

legitimate_df["domain"] = legitimate_df["url"].apply(get_domain)

legitimate_df = legitimate_df[
    ~legitimate_df["domain"].isin(phishing_domains)
]


# 6. Create final dataset
phishing_df = pd.DataFrame({
    "url": phishing,
    "label": 1
})

legitimate_df = pd.DataFrame({
    "url": legitimate_df["url"],
    "label": 0
})

dataset = pd.concat(
    [phishing_df, legitimate_df],
    ignore_index=True
)

dataset["url"] = dataset["url"].astype(str).str.strip()

dataset = dataset[
    dataset["url"].str.startswith(("http://", "https://"))
]

dataset = dataset.drop_duplicates(subset=["url"])
dataset = dataset.reset_index(drop=True)


# 7. Save
output = DATA_DIR / "urls.csv"

dataset.to_csv(output, index=False)

print("\n================================")
print("UPDATED DATASET READY")
print("================================")

print("Total URLs:", len(dataset))
print("\nClass distribution:")
print(dataset["label"].value_counts())

print("\nSaved:", output)