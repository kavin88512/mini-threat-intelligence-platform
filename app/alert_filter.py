def filter_alerts(
    results,
    priority=None,
    risk_level=None,
    enrichment_status=None
):
    """
    Filter investigation alerts using existing alert attributes.

    Parameters:
        results: List of investigation result dictionaries
        priority: P1, P2, P3, P4
        risk_level: LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN
        enrichment_status: SUCCESS, NOT_FOUND, ERROR, NOT_SUPPORTED

    Returns:
        Filtered list of alerts
    """

    filtered_results = []

    for result in results:

        if priority is not None:
            if result["Priority"] != priority:
                continue

        if risk_level is not None:
            if result["Risk Level"] != risk_level:
                continue

        if enrichment_status is not None:
            if result["Enrichment Status"] != enrichment_status:
                continue

        filtered_results.append(result)

    return filtered_results