def calculate_detection_ratio(malicious, suspicious, total_engines):
    """
    Calculate the percentage of engines that detected
    the IOC as malicious or suspicious.
    """

    if total_engines <= 0:
        return 0.0

    detections = malicious + suspicious
    ratio = (detections / total_engines) * 100

    return round(ratio, 2)


def calculate_risk_score(malicious, suspicious, total_engines):
    """
    Calculate a risk score from 0 to 100.

    Malicious detections have a much stronger impact
    than suspicious detections.
    """

    if total_engines <= 0:
        return 0.0

    malicious_ratio = malicious / total_engines
    suspicious_ratio = suspicious / total_engines

    score = (
        (malicious_ratio * 100 * 0.9)
        + (suspicious_ratio * 100 * 0.1)
    )

    return round(min(score, 100), 2)


def get_risk_level(risk_score):
    """
    Convert risk score into a risk level.
    """

    if risk_score >= 70:
        return "CRITICAL"
    elif risk_score >= 40:
        return "HIGH"
    elif risk_score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def get_recommended_action(risk_level):
    """
    Return a recommended SOC action based on risk level.
    """

    actions = {
        "LOW": "Monitor",
        "MEDIUM": "Investigate",
        "HIGH": "Investigate and escalate",
        "CRITICAL": "Immediate investigation and containment",
        "UNKNOWN": "Manual review"
    }

    return actions.get(risk_level, "Manual review")


def calculate_risk(malicious, suspicious, total_engines, reputation=None):
    """
    Calculate the complete risk assessment.

    If the IOC is not found by VirusTotal, classify it as UNKNOWN
    instead of LOW because there is not enough reputation data.
    """

    if reputation == "not_found":
        return {
            "detection_ratio": 0.0,
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "recommended_action": "Manual review"
        }

    detection_ratio = calculate_detection_ratio(
        malicious,
        suspicious,
        total_engines
    )

    risk_score = calculate_risk_score(
        malicious,
        suspicious,
        total_engines
    )

    risk_level = get_risk_level(risk_score)

    recommended_action = get_recommended_action(risk_level)

    return {
        "detection_ratio": detection_ratio,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommended_action": recommended_action
    }