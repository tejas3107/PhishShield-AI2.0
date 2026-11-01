import os
import requests
from dotenv import load_dotenv

# Load API key from the main project folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_PATH)

API_KEY = os.getenv("URLHAUS_AUTH_KEY")

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check_urlhaus(url):

    if  not API_KEY or API_KEY == "YOUR_API_KEY_HERE":
        return {
            "status": "unavailable",
            "reason": "API key not configured"
        }

    try:
        response = requests.post(
            API_URL,
            data={"url": url},
            headers={"Auth-Key": API_KEY},
            timeout=10
        )

        response.raise_for_status()
        result = response.json()

        if result.get("query_status") == "ok":
            return {
                "status": "malicious",
                "threat": result.get("threat"),
                "date_added": result.get("date_added"),
                "url_status": result.get("url_status")
            }

        elif result.get("query_status") == "no_results":
            return {
                "status": "not_found",
                "message": "URL not found in URLhaus database"
            }

        return {
            "status": "unknown",
            "details": result.get("query_status")
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }