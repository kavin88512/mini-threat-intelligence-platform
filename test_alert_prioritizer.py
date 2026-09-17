from app.alert_prioritizer import prioritize_alert


def test_critical():
    result = prioritize_alert("CRITICAL")

    assert result["priority"] == "P1"
    assert result["action"] == "Immediate investigation and containment"


def test_high():
    result = prioritize_alert("HIGH")

    assert result["priority"] == "P2"
    assert result["action"] == "Investigate and escalate"


def test_medium():
    result = prioritize_alert("MEDIUM")

    assert result["priority"] == "P3"
    assert result["action"] == "Investigate"


def test_low():
    result = prioritize_alert("LOW")

    assert result["priority"] == "P4"
    assert result["action"] == "Monitor"


def test_unknown():
    result = prioritize_alert("UNKNOWN")

    assert result["priority"] == "P4"
    assert result["action"] == "Manual review"


def test_lowercase_input():
    result = prioritize_alert("critical")

    assert result["priority"] == "P1"


def test_invalid_risk_level():
    result = prioritize_alert("INVALID")

    assert result["priority"] == "P4"
    assert result["action"] == "Manual review"


if __name__ == "__main__":
    test_critical()
    test_high()
    test_medium()
    test_low()
    test_unknown()
    test_lowercase_input()
    test_invalid_risk_level()

    print("All Phase 4 alert prioritization tests passed!")