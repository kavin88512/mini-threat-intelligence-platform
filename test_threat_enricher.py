from unittest.mock import patch, Mock

import requests

from app.threat_enricher import (
    create_empty_enrichment,
    get_supported_sources,
    get_otx_indicator_type,
    enrich_ip_with_abuseipdb,
    enrich_with_otx,
    enrich_ioc
)


def test_empty_enrichment():
    result = create_empty_enrichment()

    assert result["abuse_confidence"] is None
    assert result["abuse_reports"] is None
    assert result["country"] is None
    assert result["isp"] is None
    assert result["usage_type"] is None
    assert result["otx_pulses"] is None
    assert result["otx_threat_context"] is None
    assert result["enrichment_status"] == "NOT_FOUND"

    print("Empty enrichment structure test passed!")


def test_ip_sources():
    sources = get_supported_sources("IP Address")

    assert "AbuseIPDB" in sources
    assert "OTX" in sources

    print("IP source mapping test passed!")


def test_domain_sources():
    sources = get_supported_sources("Domain")

    assert sources == ["OTX"]

    print("Domain source mapping test passed!")


def test_url_sources():
    sources = get_supported_sources("URL")

    assert sources == ["OTX"]

    print("URL source mapping test passed!")


def test_hash_sources():
    for ioc_type in ["MD5", "SHA-1", "SHA-256"]:
        sources = get_supported_sources(ioc_type)

        assert sources == ["OTX"]

    print("Hash source mapping test passed!")


def test_otx_indicator_types():
    assert get_otx_indicator_type("IP Address") == "IPv4"
    assert get_otx_indicator_type("Domain") == "domain"
    assert get_otx_indicator_type("URL") == "URL"
    assert get_otx_indicator_type("MD5") == "file"
    assert get_otx_indicator_type("SHA-1") == "file"
    assert get_otx_indicator_type("SHA-256") == "file"

    print("OTX indicator mapping test passed!")


def test_unknown_ioc():
    sources = get_supported_sources("Unknown")

    assert sources == []

    print("Unknown IOC source mapping test passed!")


def test_unsupported_enrichment():
    result = enrich_ioc(
        "unknown-value",
        "Unknown"
    )

    assert result["enrichment_status"] == "NOT_SUPPORTED"

    print("Unsupported IOC enrichment test passed!")


# ---------------------------------------------------------
# AbuseIPDB tests
# ---------------------------------------------------------

@patch("app.threat_enricher.requests.get")
def test_abuseipdb_success(mock_get):

    mock_response = Mock()

    mock_response.status_code = 200

    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 25,
            "totalReports": 10,
            "countryName": "United States",
            "isp": "Example ISP",
            "usageType": "Data Center/Web Hosting/Transit"
        }
    }

    mock_get.return_value = mock_response

    result = enrich_ip_with_abuseipdb("1.2.3.4")

    assert result["abuse_confidence"] == 25
    assert result["abuse_reports"] == 10
    assert result["country"] == "United States"
    assert result["isp"] == "Example ISP"
    assert result["usage_type"] == "Data Center/Web Hosting/Transit"
    assert result["enrichment_status"] == "SUCCESS"

    print("AbuseIPDB success test passed!")


@patch("app.threat_enricher.requests.get")
def test_abuseipdb_api_error(mock_get):

    mock_response = Mock()
    mock_response.status_code = 401

    mock_get.return_value = mock_response

    result = enrich_ip_with_abuseipdb("1.2.3.4")

    assert result["enrichment_status"] == "ERROR"

    print("AbuseIPDB API error test passed!")


@patch("app.threat_enricher.requests.get")
def test_abuseipdb_timeout(mock_get):

    mock_get.side_effect = requests.exceptions.Timeout

    result = enrich_ip_with_abuseipdb("1.2.3.4")

    assert result["enrichment_status"] == "ERROR"

    print("AbuseIPDB timeout test passed!")


# ---------------------------------------------------------
# OTX tests
# ---------------------------------------------------------

@patch("app.threat_enricher.requests.get")
def test_otx_success(mock_get):

    mock_response = Mock()

    mock_response.status_code = 200

    mock_response.json.return_value = {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {
                    "name": "Example Malware Campaign"
                },
                {
                    "name": "Example Phishing Campaign"
                }
            ]
        }
    }

    mock_get.return_value = mock_response

    result, status = enrich_with_otx(
        "example.com",
        "Domain"
    )

    assert status == "SUCCESS"
    assert result["otx_pulses"] == 2
    assert (
        result["otx_threat_context"]
        == "Example Malware Campaign; Example Phishing Campaign"
    )

    print("OTX success test passed!")


@patch("app.threat_enricher.requests.get")
def test_otx_not_found(mock_get):

    mock_response = Mock()
    mock_response.status_code = 404

    mock_get.return_value = mock_response

    result, status = enrich_with_otx(
        "example.com",
        "Domain"
    )

    assert status == "NOT_FOUND"
    assert result["otx_pulses"] is None
    assert result["otx_threat_context"] is None

    print("OTX not found test passed!")


@patch("app.threat_enricher.requests.get")
def test_otx_api_error(mock_get):

    mock_response = Mock()
    mock_response.status_code = 500

    mock_get.return_value = mock_response

    result, status = enrich_with_otx(
        "example.com",
        "Domain"
    )

    assert status == "ERROR"

    print("OTX API error test passed!")


@patch("app.threat_enricher.requests.get")
def test_otx_timeout(mock_get):

    mock_get.side_effect = requests.exceptions.Timeout

    result, status = enrich_with_otx(
        "example.com",
        "Domain"
    )

    assert status == "ERROR"

    print("OTX timeout test passed!")


# ---------------------------------------------------------
# Missing API key tests
# ---------------------------------------------------------

@patch("app.threat_enricher.os.getenv")
def test_missing_abuseipdb_key(mock_getenv):

    mock_getenv.return_value = None

    result = enrich_ip_with_abuseipdb("1.2.3.4")

    assert result["enrichment_status"] == "ERROR"

    print("Missing AbuseIPDB API key test passed!")


@patch("app.threat_enricher.os.getenv")
def test_missing_otx_key(mock_getenv):

    mock_getenv.return_value = None

    result, status = enrich_with_otx(
        "example.com",
        "Domain"
    )

    assert status == "ERROR"

    print("Missing OTX API key test passed!")


# ---------------------------------------------------------
# Main integration interface tests
# ---------------------------------------------------------

def test_unsupported_ioc_again():

    result = enrich_ioc(
        "not-an-ioc",
        "Unknown"
    )

    assert result["enrichment_status"] == "NOT_SUPPORTED"

    print("Main interface unsupported IOC test passed!")


# ---------------------------------------------------------
# Run tests
# ---------------------------------------------------------

if __name__ == "__main__":

    test_empty_enrichment()

    test_ip_sources()
    test_domain_sources()
    test_url_sources()
    test_hash_sources()

    test_otx_indicator_types()

    test_unknown_ioc()
    test_unsupported_enrichment()

    test_abuseipdb_success()
    test_abuseipdb_api_error()
    test_abuseipdb_timeout()

    test_otx_success()
    test_otx_not_found()
    test_otx_api_error()
    test_otx_timeout()

    test_missing_abuseipdb_key()
    test_missing_otx_key()

    test_unsupported_ioc_again()

    print("\nAll Phase 5.4 tests passed!")