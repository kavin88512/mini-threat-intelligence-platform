def generate_soc_report(
    investigation_results,
    investigation_summary
):
    """
    Generate a human-readable SOC investigation report.
    """

    lines = []

    lines.append("=" * 70)
    lines.append("SOC THREAT INTELLIGENCE INVESTIGATION REPORT")
    lines.append("=" * 70)

    # Executive Summary
    lines.append("")
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append("-" * 70)

    total_iocs = investigation_summary["total_iocs"]

    lines.append(
        f"Total IOCs analysed: {total_iocs}"
    )

    lines.append(
        "The investigation identified "
        f"{investigation_summary['risk_counts']['CRITICAL']} "
        "CRITICAL, "
        f"{investigation_summary['risk_counts']['HIGH']} HIGH, "
        f"{investigation_summary['risk_counts']['MEDIUM']} MEDIUM, "
        f"{investigation_summary['risk_counts']['LOW']} LOW and "
        f"{investigation_summary['risk_counts']['UNKNOWN']} "
        "UNKNOWN risk indicators."
    )

    # Risk Summary
    lines.append("")
    lines.append("2. RISK SUMMARY")
    lines.append("-" * 70)

    risk_counts = investigation_summary["risk_counts"]

    lines.append(f"CRITICAL: {risk_counts['CRITICAL']}")
    lines.append(f"HIGH:     {risk_counts['HIGH']}")
    lines.append(f"MEDIUM:   {risk_counts['MEDIUM']}")
    lines.append(f"LOW:      {risk_counts['LOW']}")
    lines.append(f"UNKNOWN:  {risk_counts['UNKNOWN']}")

    # Priority Summary
    lines.append("")
    lines.append("3. PRIORITY SUMMARY")
    lines.append("-" * 70)

    priority_counts = investigation_summary["priority_counts"]

    lines.append(f"P1: {priority_counts['P1']}")
    lines.append(f"P2: {priority_counts['P2']}")
    lines.append(f"P3: {priority_counts['P3']}")
    lines.append(f"P4: {priority_counts['P4']}")

    # Enrichment Summary
    lines.append("")
    lines.append("4. THREAT INTELLIGENCE ENRICHMENT")
    lines.append("-" * 70)

    enrichment_counts = (
        investigation_summary["enrichment_counts"]
    )

    lines.append(
        f"Successful:    {enrichment_counts['SUCCESS']}"
    )
    lines.append(
        f"Not Found:     {enrichment_counts['NOT_FOUND']}"
    )
    lines.append(
        f"Not Supported: {enrichment_counts['NOT_SUPPORTED']}"
    )
    lines.append(
        f"Errors:        {enrichment_counts['ERROR']}"
    )

    # Highest Priority IOC
    lines.append("")
    lines.append("5. HIGHEST PRIORITY IOC")
    lines.append("-" * 70)

    highest_priority = (
        investigation_summary["highest_priority_ioc"]
    )

    if highest_priority:
        lines.append(
            f"IOC: {highest_priority['IOC']}"
        )
        lines.append(
            f"Priority: {highest_priority['Priority']}"
        )
        lines.append(
            f"Risk Level: {highest_priority['Risk Level']}"
        )
    else:
        lines.append("No priority information available.")

    # Investigation Details
    lines.append("")
    lines.append("6. IOC INVESTIGATION DETAILS")
    lines.append("-" * 70)

    for index, result in enumerate(
        investigation_results,
        start=1
    ):
        lines.append("")
        lines.append(
            f"[{index}] {result['IOC']}"
        )

        lines.append(
            f"Type: {result['Type']}"
        )

        lines.append(
            f"Risk Level: {result['Risk Level']}"
        )

        lines.append(
            f"Priority: {result['Priority']}"
        )

        lines.append(
            f"Detection Ratio: "
            f"{result['Detection Ratio']}%"
        )

        lines.append(
            f"Malicious Detections: "
            f"{result['Malicious']}"
        )

        lines.append(
            f"Suspicious Detections: "
            f"{result['Suspicious']}"
        )

        lines.append(
            f"Reputation: "
            f"{result['Reputation']}"
        )

        lines.append(
            f"Enrichment Status: "
            f"{result['Enrichment Status']}"
        )

        otx_pulses = result["OTX Pulses"]

        if otx_pulses is None:
            otx_pulses = "N/A"

        lines.append(
            f"OTX Pulses: {otx_pulses}"
        )

        lines.append(
            f"Investigation Status: "
            f"{result['Investigation Status']}"
        )

        lines.append(
            f"Investigation Reason: "
            f"{result['Investigation Reason']}"
        )

        lines.append(
            f"Analyst Recommendation: "
            f"{result['Analyst Recommendation']}"
        )

    # Closing
    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF SOC INVESTIGATION REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)