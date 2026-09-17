import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def check_reputation(ioc):
    """
    Check an IOC against the VirusTotal API
    and retrieve detection statistics.
    """

    headers = {
        "x-apikey": API_KEY
    }

    url = f"{BASE_URL}/search"

    params = {
        "query": ioc
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=10
    )

    # Handle API errors
    if response.status_code != 200:
        return {
            "ioc": ioc,
            "reputation": "error",
            "malicious": 0,
            "suspicious": 0,
            "total_engines": 0
        }

    data = response.json()

    # Handle IOC not found
    if not data.get("data"):
        return {
            "ioc": ioc,
            "reputation": "not_found",
            "malicious": 0,
            "suspicious": 0,
            "total_engines": 0
        }

    attributes = data["data"][0].get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    # Count all VirusTotal analysis engines
    total_engines = sum(stats.values())

    # Determine basic reputation
    if malicious > 0:
        reputation = "malicious"
    elif suspicious > 0:
        reputation = "suspicious"
    else:
        reputation = "clean"

    return {
        "ioc": ioc,
        "reputation": reputation,
        "malicious": malicious,
        "suspicious": suspicious,
        "total_engines": total_engines
    }