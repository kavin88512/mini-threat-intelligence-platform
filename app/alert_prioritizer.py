def prioritize_alert(risk_level):
    """
    Convert risk level into SOC alert priority and action.
    """

    risk_level = risk_level.upper()

    priority_mapping = {
        "CRITICAL": {
            "priority": "P1",
            "action": "Immediate investigation and containment"
        },
        "HIGH": {
            "priority": "P2",
            "action": "Investigate and escalate"
        },
        "MEDIUM": {
            "priority": "P3",
            "action": "Investigate"
        },
        "LOW": {
            "priority": "P4",
            "action": "Monitor"
        },
        "UNKNOWN": {
            "priority": "P4",
            "action": "Manual review"
        }
    }

    return priority_mapping.get(
        risk_level,
        {
            "priority": "P4",
            "action": "Manual review"
        }
    )