from app.investigation_summary import (
    generate_investigation_summary
)


def sample_results():
    return [
        {
            "IOC": "8.8.8.8",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "SUCCESS",
            "Investigation Status": "NEW"
        },
        {
            "IOC": "44d88612fea8a8f36de82e1278abb02f",
            "Risk Level": "CRITICAL",
            "Priority": "P1",
            "Enrichment Status": "SUCCESS",
            "Investigation Status": "NEW"
        },
        {
            "IOC": "google.com",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "SUCCESS",
            "Investigation Status": "NEW"
        },
        {
            "IOC": "https://example.com/login",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "NOT_FOUND",
            "Investigation Status": "NEW"
        },
        {
            "IOC": "hello123",
            "Risk Level": "UNKNOWN",
            "Priority": "P4",
            "Enrichment Status": "NOT_SUPPORTED",
            "Investigation Status": "NEW"
        }
    ]


def test_total_iocs():
    results = sample_results()

    summary = generate_investigation_summary(results)

    assert summary["total_iocs"] == 5


def test_risk_counts():
    results = sample_results()

    summary = generate_investigation_summary(results)

    assert summary["risk_counts"]["CRITICAL"] == 1
    assert summary["risk_counts"]["HIGH"] == 0
    assert summary["risk_counts"]["MEDIUM"] == 0
    assert summary["risk_counts"]["LOW"] == 3
    assert summary["risk_counts"]["UNKNOWN"] == 1


def test_priority_counts():
    results = sample_results()

    summary = generate_investigation_summary(results)

    assert summary["priority_counts"]["P1"] == 1
    assert summary["priority_counts"]["P2"] == 0
    assert summary["priority_counts"]["P3"] == 0
    assert summary["priority_counts"]["P4"] == 4


def test_enrichment_counts():
    results = sample_results()

    summary = generate_investigation_summary(results)

    assert summary["enrichment_counts"]["SUCCESS"] == 3
    assert summary["enrichment_counts"]["NOT_FOUND"] == 1
    assert summary["enrichment_counts"]["NOT_SUPPORTED"] == 1
    assert summary["enrichment_counts"]["ERROR"] == 0


def test_investigation_status():
    results = sample_results()

    summary = generate_investigation_summary(results)

    assert summary["status_counts"]["NEW"] == 5


def test_highest_priority_ioc():
    results = sample_results()

    summary = generate_investigation_summary(results)

    highest_priority = summary["highest_priority_ioc"]

    assert highest_priority["IOC"] == (
        "44d88612fea8a8f36de82e1278abb02f"
    )

    assert highest_priority["Priority"] == "P1"
    assert highest_priority["Risk Level"] == "CRITICAL"


def test_empty_results():
    summary = generate_investigation_summary([])

    assert summary["total_iocs"] == 0
    assert summary["highest_priority_ioc"] is None


print("All Phase 6.3 investigation summary tests passed!")