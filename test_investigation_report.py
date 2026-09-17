from app.investigation_report import (
    generate_investigation_reason,
    generate_analyst_recommendation,
    create_investigation_report
)


def test_critical_p1():
    result = {
        "IOC": "44d88612fea8a8f36de82e1278abb02f",
        "Type": "MD5 Hash",
        "Risk Level": "CRITICAL",
        "Priority": "P1",
        "Detection Ratio": 89.19,
        "Malicious": 66,
        "Suspicious": 0,
        "Reputation": "malicious",
        "Enrichment Status": "SUCCESS",
        "OTX Pulses": 50
    }

    reason = generate_investigation_reason(result)
    recommendation = generate_analyst_recommendation(result)

    assert "CRITICAL" in reason
    assert "89.19%" in reason
    assert "P1" in reason
    assert "Immediate investigation" in recommendation
    assert "OTX" in recommendation


def test_low_clean_ioc():
    result = {
        "IOC": "8.8.8.8",
        "Type": "IP Address",
        "Risk Level": "LOW",
        "Priority": "P4",
        "Detection Ratio": 0.0,
        "Malicious": 0,
        "Suspicious": 0,
        "Reputation": "clean",
        "Enrichment Status": "SUCCESS",
        "OTX Pulses": 0
    }

    reason = generate_investigation_reason(result)
    recommendation = generate_analyst_recommendation(result)

    assert "No significant malicious or suspicious detections" in reason
    assert "Monitor" in recommendation


def test_unknown_ioc():
    result = {
        "IOC": "hello123",
        "Type": "Unknown",
        "Risk Level": "UNKNOWN",
        "Priority": "P4",
        "Detection Ratio": 0.0,
        "Malicious": 0,
        "Suspicious": 0,
        "Reputation": "not_found",
        "Enrichment Status": "NOT_SUPPORTED",
        "OTX Pulses": 0
    }

    reason = generate_investigation_reason(result)
    recommendation = generate_analyst_recommendation(result)

    assert "unavailable" in reason
    assert "Manual investigation" in recommendation


def test_not_found_enrichment():
    result = {
        "IOC": "https://example.com/login",
        "Type": "URL",
        "Risk Level": "LOW",
        "Priority": "P4",
        "Detection Ratio": 0.0,
        "Malicious": 0,
        "Suspicious": 0,
        "Reputation": "clean",
        "Enrichment Status": "NOT_FOUND",
        "OTX Pulses": 0
    }

    reason = generate_investigation_reason(result)

    assert "did not return a matching record" in reason


def test_investigation_report_creation():
    results = [
        {
            "IOC": "8.8.8.8",
            "Type": "IP Address",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Detection Ratio": 0.0,
            "Malicious": 0,
            "Suspicious": 0,
            "Reputation": "clean",
            "Enrichment Status": "SUCCESS",
            "OTX Pulses": 0
        }
    ]

    report = create_investigation_report(results)

    assert len(report) == 1
    assert report[0]["IOC"] == "8.8.8.8"
    assert report[0]["Investigation Status"] == "NEW"
    assert "Investigation Reason" in report[0]
    assert "Analyst Recommendation" in report[0]


print("All Phase 6.1 investigation report tests passed!")