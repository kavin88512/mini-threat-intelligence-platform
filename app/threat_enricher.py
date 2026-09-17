"""
Threat Intelligence Enrichment Module

Phase 5
AbuseIPDB + AlienVault OTX enrichment.
"""

import os
import requests
from dotenv import load_dotenv


load_dotenv()


ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_API_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"


def create_empty_enrichment():
    """
    Return the default enrichment structure.
    """

    return {
        "abuse_confidence": None,
        "abuse_reports": None,
        "country": None,
        "isp": None,
        "usage_type": None,
        "otx_pulses": None,
        "otx_threat_context": None,
        "enrichment_status": "NOT_FOUND"
    }


def get_supported_sources(ioc_type):
    mapping = {
        "IP Address": ["AbuseIPDB", "OTX"],
        "Domain": ["OTX"],
        "URL": ["OTX"],
        "MD5": ["OTX"],
        "MD5 Hash": ["OTX"],
        "SHA-1": ["OTX"],
        "SHA-1 Hash": ["OTX"],
        "SHA-256": ["OTX"],
        "SHA-256 Hash": ["OTX"],
        "Unknown": []
    }

    return mapping.get(ioc_type, [])


def enrich_ip_with_abuseipdb(ip_address):
    """
    Enrich an IP address using AbuseIPDB.
    """

    result = create_empty_enrichment()

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        result["enrichment_status"] = "ERROR"
        return result

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code != 200:
            result["enrichment_status"] = "ERROR"
            return result

        response_data = response.json()
        data = response_data.get("data")

        if not data:
            result["enrichment_status"] = "NOT_FOUND"
            return result

        result["abuse_confidence"] = data.get(
            "abuseConfidenceScore"
        )

        result["abuse_reports"] = data.get(
            "totalReports"
        )

        result["country"] = data.get(
            "countryName"
        )

        result["isp"] = data.get(
            "isp"
        )

        result["usage_type"] = data.get(
            "usageType"
        )

        result["enrichment_status"] = "SUCCESS"

        return result

    except requests.RequestException:
        result["enrichment_status"] = "ERROR"
        return result

    except ValueError:
        result["enrichment_status"] = "ERROR"
        return result


def get_otx_indicator_type(ioc_type):
    mapping = {
        "IP Address": "IPv4",
        "Domain": "domain",
        "URL": "URL",
        "MD5": "file",
        "MD5 Hash": "file",
        "SHA-1": "file",
        "SHA-1 Hash": "file",
        "SHA-256": "file",
        "SHA-256 Hash": "file"
    }

    return mapping.get(ioc_type)


def enrich_with_otx(ioc, ioc_type):
    """
    Enrich an IOC using AlienVault OTX.
    """

    result = {
        "otx_pulses": None,
        "otx_threat_context": None
    }

    api_key = os.getenv("OTX_API_KEY")

    if not api_key:
        return result, "ERROR"

    indicator_type = get_otx_indicator_type(ioc_type)

    if not indicator_type:
        return result, "NOT_SUPPORTED"

    url = (
        f"{OTX_API_BASE_URL}/"
        f"{indicator_type}/"
        f"{ioc}/general"
    )

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            return result, "NOT_FOUND"

        if response.status_code != 200:
            return result, "ERROR"

        data = response.json()

        pulse_info = data.get("pulse_info", {})

        pulse_count = pulse_info.get(
            "count",
            0
        )

        result["otx_pulses"] = pulse_count

        pulses = pulse_info.get("pulses", [])

        # Extract unique threat names
        threat_names = []
        seen_names = set()

        for pulse in pulses:
            name = pulse.get("name")

            if name and name not in seen_names:
                threat_names.append(name)
                seen_names.add(name)

        # Keep only the first 5 unique threat names
        if threat_names:
            result["otx_threat_context"] = "; ".join(
                threat_names[:5]
            )

        return result, "SUCCESS"

    except requests.RequestException:
        return result, "ERROR"

    except ValueError:
        return result, "ERROR"


def enrich_ioc(ioc, ioc_type):
    """
    Main enrichment interface.
    """

    enrichment = create_empty_enrichment()

    sources = get_supported_sources(ioc_type)

    if not sources:
        enrichment["enrichment_status"] = "NOT_SUPPORTED"
        return enrichment

    statuses = []

    # AbuseIPDB
    if "AbuseIPDB" in sources:
        abuse_result = enrich_ip_with_abuseipdb(ioc)

        for key in [
            "abuse_confidence",
            "abuse_reports",
            "country",
            "isp",
            "usage_type"
        ]:
            enrichment[key] = abuse_result.get(key)

        statuses.append(
            abuse_result.get("enrichment_status")
        )

    # OTX
    if "OTX" in sources:
        otx_result, otx_status = enrich_with_otx(
            ioc,
            ioc_type
        )

        enrichment["otx_pulses"] = otx_result.get(
            "otx_pulses"
        )

        enrichment["otx_threat_context"] = otx_result.get(
            "otx_threat_context"
        )

        statuses.append(otx_status)

    # Determine overall status
    if "SUCCESS" in statuses:
        enrichment["enrichment_status"] = "SUCCESS"

    elif "ERROR" in statuses:
        enrichment["enrichment_status"] = "ERROR"

    elif "NOT_FOUND" in statuses:
        enrichment["enrichment_status"] = "NOT_FOUND"

    else:
        enrichment["enrichment_status"] = "NOT_SUPPORTED"

    return enrichment