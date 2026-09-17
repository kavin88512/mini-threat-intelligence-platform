import csv
import os


VALID_STATUSES = {
    "NEW",
    "IN PROGRESS",
    "CLOSED"
}


INVESTIGATION_FIELDNAMES = [
    "IOC",
    "Type",
    "Risk Level",
    "Priority",
    "Detection Ratio",
    "Malicious",
    "Suspicious",
    "Reputation",
    "Enrichment Status",
    "OTX Pulses",
    "Investigation Status",
    "Investigation Reason",
    "Analyst Recommendation",
    "Analyst Note"
]


def update_investigation_status(
    result,
    new_status,
    analyst_note=""
):
    """
    Update the investigation status and analyst note.
    """

    new_status = new_status.strip().upper()

    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid investigation status: {new_status}"
        )

    result["Investigation Status"] = new_status
    result["Analyst Note"] = analyst_note.strip()

    return result


def get_investigation_details(result):
    """
    Return the main investigation details for an IOC.
    """

    return {
        "IOC": result["IOC"],
        "Type": result["Type"],
        "Risk Level": result["Risk Level"],
        "Priority": result["Priority"],
        "Detection Ratio": result["Detection Ratio"],
        "Reputation": result["Reputation"],
        "Enrichment Status": result["Enrichment Status"],
        "OTX Pulses": result["OTX Pulses"],
        "Investigation Status": result["Investigation Status"],
        "Investigation Reason": result[
            "Investigation Reason"
        ],
        "Analyst Recommendation": result[
            "Analyst Recommendation"
        ],
        "Analyst Note": result.get(
            "Analyst Note",
            ""
        )
    }


def display_investigation_details(result):
    """
    Display investigation details for an IOC.
    """

    details = get_investigation_details(result)

    print()
    print("=== Investigation Details ===")
    print(f"IOC: {details['IOC']}")
    print(f"Type: {details['Type']}")
    print(f"Risk Level: {details['Risk Level']}")
    print(f"Priority: {details['Priority']}")
    print(
        f"Detection Ratio: "
        f"{details['Detection Ratio']}%"
    )
    print(f"Reputation: {details['Reputation']}")
    print(
        f"Enrichment Status: "
        f"{details['Enrichment Status']}"
    )

    otx_pulses = details["OTX Pulses"]

    if otx_pulses is None:
        otx_pulses = "N/A"

    print(f"OTX Pulses: {otx_pulses}")

    print(
        f"Investigation Status: "
        f"{details['Investigation Status']}"
    )

    print(
        f"Investigation Reason: "
        f"{details['Investigation Reason']}"
    )

    print(
        f"Analyst Recommendation: "
        f"{details['Analyst Recommendation']}"
    )

    analyst_note = details["Analyst Note"]

    if analyst_note:
        print(f"Analyst Note: {analyst_note}")
    else:
        print("Analyst Note: None")


def load_investigation_state(file_path):
    """
    Load previously saved investigation status and analyst notes.

    Returns:
        Dictionary indexed by IOC.
    """

    state = {}

    if not os.path.exists(file_path):
        return state

    with open(
        file_path,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            ioc = row.get("IOC")

            if not ioc:
                continue

            status = row.get(
                "Investigation Status",
                "NEW"
            )

            analyst_note = row.get(
                "Analyst Note",
                ""
            )

            state[ioc] = {
                "Investigation Status": (
                    status.strip()
                    if status
                    else "NEW"
                ),
                "Analyst Note": (
                    analyst_note.strip()
                    if analyst_note
                    else ""
                )
            }

    return state


def apply_saved_investigation_state(
    results,
    saved_state
):
    """
    Apply previously saved investigation status
    and analyst notes to fresh investigation results.
    """

    for result in results:

        ioc = result["IOC"]

        if ioc not in saved_state:
            result.setdefault(
                "Investigation Status",
                "NEW"
            )

            result.setdefault(
                "Analyst Note",
                ""
            )

            continue

        saved = saved_state[ioc]

        result["Investigation Status"] = (
            saved["Investigation Status"]
        )

        result["Analyst Note"] = (
            saved["Analyst Note"]
        )

    return results


def save_investigation_results(
    results,
    file_path
):
    """
    Save investigation results to CSV.
    """

    directory = os.path.dirname(file_path)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=INVESTIGATION_FIELDNAMES,
            extrasaction="ignore"
        )

        writer.writeheader()

        for result in results:

            result.setdefault(
                "Analyst Note",
                ""
            )

            writer.writerow(result)