from app.soc_report import generate_soc_report


def test_generate_soc_report():

    investigation_results = [
        {
            "IOC": "44d88612fea8a8f36de82e1278abb02f",
            "Type": "MD5 Hash",
            "Risk Level": "CRITICAL",
            "Priority": "P1",
            "Detection Ratio": 89.19,
            "Malicious": 66,
            "Suspicious": 0,
            "Reputation": "malicious",
            "Enrichment Status": "SUCCESS",
            "OTX Pulses": 50,
            "Investigation Status": "NEW",
            "Investigation Reason": (
                "High malicious detection ratio reported."
            ),
            "Analyst Recommendation": (
                "Immediate investigation and containment."
            )
        }
    ]

    investigation_summary = {
        "total_iocs": 1,

        "risk_counts": {
            "CRITICAL": 1,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        },

        "priority_counts": {
            "P1": 1,
            "P2": 0,
            "P3": 0,
            "P4": 0
        },

        "enrichment_counts": {
            "SUCCESS": 1,
            "NOT_FOUND": 0,
            "NOT_SUPPORTED": 0,
            "ERROR": 0
        },

        "status_counts": {
            "NEW": 1
        },

        "highest_priority_ioc": {
            "IOC": "44d88612fea8a8f36de82e1278abb02f",
            "Priority": "P1",
            "Risk Level": "CRITICAL"
        }
    }

    report = generate_soc_report(
        investigation_results,
        investigation_summary
    )

    assert "SOC THREAT INTELLIGENCE INVESTIGATION REPORT" in report
    assert "EXECUTIVE SUMMARY" in report
    assert "RISK SUMMARY" in report
    assert "PRIORITY SUMMARY" in report
    assert "THREAT INTELLIGENCE ENRICHMENT" in report
    assert "HIGHEST PRIORITY IOC" in report
    assert "44d88612fea8a8f36de82e1278abb02f" in report
    assert "CRITICAL" in report
    assert "P1" in report
    assert "89.19" in report
    assert "66" in report
    assert "50" in report
    assert "Immediate investigation" in report
    assert "END OF SOC INVESTIGATION REPORT" in report


def test_empty_report():

    investigation_summary = {
        "total_iocs": 0,

        "risk_counts": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        },

        "priority_counts": {
            "P1": 0,
            "P2": 0,
            "P3": 0,
            "P4": 0
        },

        "enrichment_counts": {
            "SUCCESS": 0,
            "NOT_FOUND": 0,
            "NOT_SUPPORTED": 0,
            "ERROR": 0
        },

        "status_counts": {},

        "highest_priority_ioc": None
    }

    report = generate_soc_report(
        [],
        investigation_summary
    )

    assert "Total IOCs analysed: 0" in report
    assert "No priority information available." in report


print("All Phase 6.5 SOC report tests passed!")