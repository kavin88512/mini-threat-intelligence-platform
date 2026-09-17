from app.alert_filter import filter_alerts


def sample_results():
    return [
        {
            "IOC": "8.8.8.8",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "SUCCESS"
        },
        {
            "IOC": "44d88612fea8a8f36de82e1278abb02f",
            "Risk Level": "CRITICAL",
            "Priority": "P1",
            "Enrichment Status": "SUCCESS"
        },
        {
            "IOC": "google.com",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "SUCCESS"
        },
        {
            "IOC": "https://example.com/login",
            "Risk Level": "LOW",
            "Priority": "P4",
            "Enrichment Status": "NOT_FOUND"
        },
        {
            "IOC": "hello123",
            "Risk Level": "UNKNOWN",
            "Priority": "P4",
            "Enrichment Status": "NOT_SUPPORTED"
        }
    ]


def test_filter_p1():
    results = sample_results()

    filtered = filter_alerts(
        results,
        priority="P1"
    )

    assert len(filtered) == 1
    assert filtered[0]["IOC"] == "44d88612fea8a8f36de82e1278abb02f"


def test_filter_p4():
    results = sample_results()

    filtered = filter_alerts(
        results,
        priority="P4"
    )

    assert len(filtered) == 4


def test_filter_critical():
    results = sample_results()

    filtered = filter_alerts(
        results,
        risk_level="CRITICAL"
    )

    assert len(filtered) == 1
    assert filtered[0]["Risk Level"] == "CRITICAL"


def test_filter_unknown():
    results = sample_results()

    filtered = filter_alerts(
        results,
        risk_level="UNKNOWN"
    )

    assert len(filtered) == 1
    assert filtered[0]["IOC"] == "hello123"


def test_filter_not_found_enrichment():
    results = sample_results()

    filtered = filter_alerts(
        results,
        enrichment_status="NOT_FOUND"
    )

    assert len(filtered) == 1
    assert filtered[0]["IOC"] == "https://example.com/login"


def test_multiple_filters():
    results = sample_results()

    filtered = filter_alerts(
        results,
        priority="P4",
        enrichment_status="SUCCESS"
    )

    assert len(filtered) == 2


def test_no_filters():
    results = sample_results()

    filtered = filter_alerts(results)

    assert len(filtered) == len(results)


print("All Phase 6.2 alert filtering tests passed!")