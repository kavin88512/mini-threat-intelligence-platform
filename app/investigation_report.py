def generate_investigation_reason(result):
    """
    Generate a SOC investigation reason based on existing
    reputation, risk and enrichment information.
    """

    risk_level = result["Risk Level"]
    priority = result["Priority"]
    reputation = result["Reputation"]
    malicious = int(result["Malicious"])
    suspicious = int(result["Suspicious"])
    detection_ratio = float(result["Detection Ratio"])
    enrichment_status = result["Enrichment Status"]
    otx_pulses = int(result["OTX Pulses"] or 0)

    if risk_level == "CRITICAL":
        reason = (
            f"High malicious detection ratio reported by VirusTotal "
            f"({detection_ratio:.2f}%). "
            f"IOC is classified as CRITICAL and assigned {priority} priority."
        )

    elif risk_level == "HIGH":
        reason = (
            f"Significant malicious activity was detected by VirusTotal "
            f"({malicious} malicious detections, "
            f"{detection_ratio:.2f}% detection ratio). "
            f"IOC is classified as HIGH risk and assigned {priority} priority."
        )

    elif risk_level == "MEDIUM":
        reason = (
            f"Moderate malicious or suspicious activity was detected. "
            f"VirusTotal reported {malicious} malicious and "
            f"{suspicious} suspicious detections."
        )

    elif risk_level == "LOW":
        if malicious > 0 or suspicious > 0:
            reason = (
                f"Limited reputation detections were identified. "
                f"VirusTotal reported {malicious} malicious and "
                f"{suspicious} suspicious detections. "
                f"Current risk classification is LOW."
            )
        else:
            reason = (
                "No significant malicious or suspicious detections "
                "were identified by VirusTotal."
            )

    elif risk_level == "UNKNOWN":
        reason = (
            "Automated reputation information is unavailable. "
            "Manual investigation is required because available "
            "reputation evidence is insufficient."
        )

    else:
        reason = "Risk classification requires manual review."

    # Add enrichment context when available
    if enrichment_status == "SUCCESS" and otx_pulses > 0:
        reason += (
            f" OTX enrichment returned {otx_pulses} related threat "
            "intelligence pulse(s) for further investigation."
        )

    elif enrichment_status == "NOT_FOUND":
        reason += (
            " The enrichment source did not return a matching record."
        )

    elif enrichment_status == "NOT_SUPPORTED":
        reason += (
            " Threat intelligence enrichment is not supported "
            "for this IOC."
        )

    elif enrichment_status == "ERROR":
        reason += (
            " Threat intelligence enrichment encountered an error."
        )

    return reason


def generate_analyst_recommendation(result):
    """
    Generate a SOC analyst recommendation based on
    the existing alert priority and available evidence.
    """

    priority = result["Priority"]
    risk_level = result["Risk Level"]
    enrichment_status = result["Enrichment Status"]
    otx_pulses = int(result["OTX Pulses"] or 0)

    if priority == "P1":
        recommendation = (
            "Immediate investigation and containment. "
            "Review affected endpoints, network activity, "
            "security logs and related IOCs."
        )

    elif priority == "P2":
        recommendation = (
            "Investigate and escalate. Review affected systems, "
            "related indicators, network activity and recent "
            "security events."
        )

    elif priority == "P3":
        recommendation = (
            "Investigate the IOC and correlate it with available "
            "security logs and related indicators."
        )

    elif risk_level == "UNKNOWN":
        recommendation = (
            "Perform manual investigation because automated "
            "reputation information is unavailable."
        )

    else:
        recommendation = (
            "Monitor the IOC and retain it for future correlation."
        )

    # Add enrichment-specific recommendation
    if enrichment_status == "SUCCESS" and otx_pulses > 0:
        recommendation += (
            " Review the available OTX threat context and related "
            "threat intelligence pulses."
        )

    return recommendation


def create_investigation_report(results):
    """
    Create SOC investigation records from the existing
    Phase 1-5 pipeline results.
    """

    investigation_results = []

    for result in results:

        investigation_results.append({
            "IOC": result["IOC"],
            "Type": result["Type"],
            "Risk Level": result["Risk Level"],
            "Priority": result["Priority"],
            "Detection Ratio": result["Detection Ratio"],
            "Malicious": result["Malicious"],
            "Suspicious": result["Suspicious"],
            "Reputation": result["Reputation"],
            "Enrichment Status": result["Enrichment Status"],
            "OTX Pulses": result["OTX Pulses"],
            "Investigation Status": "NEW",
            "Investigation Reason": generate_investigation_reason(result),
            "Analyst Recommendation": generate_analyst_recommendation(result)
        })

    return investigation_results