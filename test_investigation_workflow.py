import os

from app.investigation_workflow import (
    update_investigation_status,
    get_investigation_details,
    save_investigation_results,
    load_investigation_state,
    apply_saved_investigation_state
)


TEST_FILE = "test_investigation_state.csv"


def create_test_result():
    return {
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
            "High malicious detection ratio."
        ),
        "Analyst Recommendation": (
            "Immediate investigation and containment."
        ),
        "Analyst Note": ""
    }


# --------------------------------------------------
# Test 1: NEW -> IN PROGRESS
# --------------------------------------------------

result = create_test_result()

update_investigation_status(
    result,
    "IN PROGRESS",
    "Started investigation of the malicious hash."
)

assert result["Investigation Status"] == "IN PROGRESS"

assert (
    result["Analyst Note"]
    == "Started investigation of the malicious hash."
)


# --------------------------------------------------
# Test 2: IN PROGRESS -> CLOSED
# --------------------------------------------------

update_investigation_status(
    result,
    "CLOSED",
    "Investigation completed and evidence reviewed."
)

assert result["Investigation Status"] == "CLOSED"

assert (
    result["Analyst Note"]
    == "Investigation completed and evidence reviewed."
)


# --------------------------------------------------
# Test 3: Investigation details
# --------------------------------------------------

details = get_investigation_details(result)

assert details["IOC"] == (
    "44d88612fea8a8f36de82e1278abb02f"
)

assert details["Priority"] == "P1"

assert details["Risk Level"] == "CRITICAL"

assert details["Investigation Status"] == "CLOSED"

assert (
    details["Analyst Note"]
    == "Investigation completed and evidence reviewed."
)


# --------------------------------------------------
# Test 4: Invalid status
# --------------------------------------------------

try:

    update_investigation_status(
        result,
        "INVALID"
    )

    assert False, (
        "Invalid status should raise ValueError"
    )

except ValueError:
    pass


# --------------------------------------------------
# Test 5: Save investigation state
# --------------------------------------------------

save_investigation_results(
    [result],
    TEST_FILE
)

assert os.path.exists(TEST_FILE), (
    "Investigation state file was not created"
)


# --------------------------------------------------
# Test 6: Load investigation state
# --------------------------------------------------

saved_state = load_investigation_state(
    TEST_FILE
)

assert (
    "44d88612fea8a8f36de82e1278abb02f"
    in saved_state
)

assert (
    saved_state[
        "44d88612fea8a8f36de82e1278abb02f"
    ]["Investigation Status"]
    == "CLOSED"
)

assert (
    saved_state[
        "44d88612fea8a8f36de82e1278abb02f"
    ]["Analyst Note"]
    == "Investigation completed and evidence reviewed."
)


# --------------------------------------------------
# Test 7: Apply saved state to a fresh result
# --------------------------------------------------

fresh_result = create_test_result()

assert fresh_result["Investigation Status"] == "NEW"

apply_saved_investigation_state(
    [fresh_result],
    saved_state
)

assert (
    fresh_result["Investigation Status"]
    == "CLOSED"
)

assert (
    fresh_result["Analyst Note"]
    == "Investigation completed and evidence reviewed."
)


# --------------------------------------------------
# Test 8: Fresh intelligence data is preserved
# --------------------------------------------------

assert fresh_result["IOC"] == (
    "44d88612fea8a8f36de82e1278abb02f"
)

assert fresh_result["Risk Level"] == "CRITICAL"

assert fresh_result["Priority"] == "P1"

assert fresh_result["Detection Ratio"] == 89.19

assert fresh_result["Malicious"] == 66

assert fresh_result["Reputation"] == "malicious"


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

if os.path.exists(TEST_FILE):
    os.remove(TEST_FILE)


print(
    "All Phase 6.6 investigation workflow tests passed!"
)
print(
    "Persistence save/load test passed!"
)