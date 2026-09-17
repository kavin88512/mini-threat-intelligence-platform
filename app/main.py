import csv

from ioc_analyzer import identify_ioc, normalize_ioc
from reputation_checker import check_reputation
from risk_scorer import calculate_risk
from alert_prioritizer import prioritize_alert
from threat_enricher import enrich_ioc
from investigation_report import create_investigation_report
from alert_filter import filter_alerts
from investigation_summary import (
    generate_investigation_summary,
    print_investigation_summary
)
from soc_report import generate_soc_report
from investigation_workflow import (
    update_investigation_status,
    display_investigation_details,
    load_investigation_state,
    apply_saved_investigation_state,
    save_investigation_results
)


def display_investigation_queue(
    results,
    title="All Alerts"
):
    print()
    print(
        f"=== SOC Investigation Queue: {title} ==="
    )

    if not results:
        print(
            "No alerts matched the selected filter."
        )
        return

    for index, result in enumerate(
        results,
        start=1
    ):
        print()
        print(
            f"[{index}] IOC: {result['IOC']}"
        )

        print(
            f"    Type: {result['Type']}"
        )

        print(
            f"    Risk Level: {result['Risk Level']}"
        )

        print(
            f"    Priority: {result['Priority']}"
        )

        print(
            f"    Detection Ratio: "
            f"{result['Detection Ratio']}%"
        )

        print(
            f"    Reputation: "
            f"{result['Reputation']}"
        )

        print(
            f"    Enrichment Status: "
            f"{result['Enrichment Status']}"
        )

        otx_pulses = result["OTX Pulses"]

        if otx_pulses is None:
            otx_pulses = "N/A"

        print(
            f"    OTX Pulses: {otx_pulses}"
        )

        print(
            f"    Investigation Status: "
            f"{result['Investigation Status']}"
        )

        print(
            f"    Reason: "
            f"{result['Investigation Reason']}"
        )

        print(
            f"    Recommendation: "
            f"{result['Analyst Recommendation']}"
        )

        analyst_note = result.get(
            "Analyst Note",
            ""
        )

        if analyst_note:
            print(
                f"    Analyst Note: "
                f"{analyst_note}"
            )


def investigate_ioc(
    investigation_results
):
    print()
    print("=== IOC Investigation ===")

    if not investigation_results:
        print(
            "No investigation records available."
        )
        return

    for index, result in enumerate(
        investigation_results,
        start=1
    ):
        print(
            f"{index}. "
            f"{result['IOC']} | "
            f"{result['Priority']} | "
            f"{result['Risk Level']} | "
            f"{result['Investigation Status']}"
        )

    print()

    selection = input(
        "Select IOC number: "
    ).strip()

    if not selection.isdigit():
        print("Invalid selection.")
        return

    index = int(selection)

    if (
        index < 1
        or index > len(investigation_results)
    ):
        print("Invalid IOC number.")
        return

    result = investigation_results[
        index - 1
    ]

    display_investigation_details(
        result
    )

    print()
    print("=== Update Investigation ===")
    print("1. Mark as IN PROGRESS")
    print("2. Mark as CLOSED")
    print("3. Add / Update Analyst Note")
    print("4. Return")

    action = input(
        "Select an action: "
    ).strip()

    investigation_output_file = (
        "reports/soc_investigation_report.csv"
    )

    if action == "1":
        note = input(
            "Enter analyst note: "
        ).strip()

        try:
            update_investigation_status(
                result,
                "IN PROGRESS",
                note
            )

            # Save workflow state immediately
            save_investigation_results(
                investigation_results,
                investigation_output_file
            )

            print(
                "Investigation status updated "
                "to IN PROGRESS."
            )

            print(
                "Investigation state saved."
            )

        except ValueError as error:
            print(f"Error: {error}")

    elif action == "2":
        note = input(
            "Enter analyst note: "
        ).strip()

        try:
            update_investigation_status(
                result,
                "CLOSED",
                note
            )

            # Save workflow state immediately
            save_investigation_results(
                investigation_results,
                investigation_output_file
            )

            print(
                "Investigation status updated "
                "to CLOSED."
            )

            print(
                "Investigation state saved."
            )

        except ValueError as error:
            print(f"Error: {error}")

    elif action == "3":
        note = input(
            "Enter analyst note: "
        ).strip()

        result["Analyst Note"] = note

        # Save analyst note immediately
        save_investigation_results(
            investigation_results,
            investigation_output_file
        )

        print(
            "Analyst note updated."
        )

        print(
            "Investigation state saved."
        )

    elif action == "4":
        print(
            "Returning to investigation queue."
        )

    else:
        print("Invalid selection.")


def show_investigation_queue(
    investigation_results
):
    print()
    print("=== SOC Investigation Queue ===")
    print("1. All Alerts")
    print("2. P1 Critical")
    print("3. P2 High")
    print("4. P3 Medium")
    print("5. P4 Low/Unknown")
    print("6. Critical Risk")
    print("7. High Risk")
    print("8. Unknown Risk")
    print("9. Investigate IOC")
    print("10. Exit")

    choice = input(
        "Select an option: "
    ).strip()

    if choice == "1":
        filtered_results = (
            investigation_results
        )
        title = "All Alerts"

    elif choice == "2":
        filtered_results = filter_alerts(
            investigation_results,
            priority="P1"
        )
        title = "P1 Critical"

    elif choice == "3":
        filtered_results = filter_alerts(
            investigation_results,
            priority="P2"
        )
        title = "P2 High"

    elif choice == "4":
        filtered_results = filter_alerts(
            investigation_results,
            priority="P3"
        )
        title = "P3 Medium"

    elif choice == "5":
        filtered_results = filter_alerts(
            investigation_results,
            priority="P4"
        )
        title = "P4 Low/Unknown"

    elif choice == "6":
        filtered_results = filter_alerts(
            investigation_results,
            risk_level="CRITICAL"
        )
        title = "Critical Risk"

    elif choice == "7":
        filtered_results = filter_alerts(
            investigation_results,
            risk_level="HIGH"
        )
        title = "High Risk"

    elif choice == "8":
        filtered_results = filter_alerts(
            investigation_results,
            risk_level="UNKNOWN"
        )
        title = "Unknown Risk"

    elif choice == "9":
        investigate_ioc(
            investigation_results
        )
        return

    elif choice == "10":
        print(
            "Exiting investigation queue."
        )
        return

    else:
        print("Invalid selection.")
        return

    display_investigation_queue(
        filtered_results,
        title
    )


def main():
    print(
        "=== Mini Threat Intelligence Platform ==="
    )

    print(
        "IOC Analyzer + Reputation Checker "
        "+ Risk Scoring + Alert Prioritisation"
    )

    print()

    input_file = "data/iocs.txt"

    output_file = (
        "reports/ioc_analysis.csv"
    )

    investigation_output_file = (
        "reports/soc_investigation_report.csv"
    )

    soc_report_output_file = (
        "reports/soc_investigation_report.txt"
    )

    try:
        with open(
            input_file,
            "r"
        ) as file:
            iocs = file.readlines()

    except FileNotFoundError:
        print(
            f"Error: {input_file} was not found."
        )
        return

    results = []

    priority_counts = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0
    }

    for ioc in iocs:
        ioc = ioc.strip()

        if not ioc:
            continue

        # Phase 1:
        # Identify and normalize IOC
        ioc_type = identify_ioc(ioc)

        normalized_ioc = normalize_ioc(
            ioc,
            ioc_type
        )

        # Phase 2:
        # VirusTotal reputation
        reputation_result = check_reputation(
            normalized_ioc
        )

        # Phase 5:
        # Threat Intelligence Enrichment
        enrichment_result = enrich_ioc(
            normalized_ioc,
            ioc_type
        )

        # Phase 3:
        # Risk calculation
        risk_result = calculate_risk(
            malicious=reputation_result[
                "malicious"
            ],
            suspicious=reputation_result[
                "suspicious"
            ],
            total_engines=reputation_result[
                "total_engines"
            ],
            reputation=reputation_result[
                "reputation"
            ]
        )

        # Phase 4:
        # Alert prioritisation
        alert_result = prioritize_alert(
            risk_result["risk_level"]
        )

        priority = alert_result[
            "priority"
        ]

        priority_counts[
            priority
        ] += 1

        results.append({
            "IOC": ioc,
            "Type": ioc_type,
            "Normalized IOC": normalized_ioc,
            "Reputation": reputation_result[
                "reputation"
            ],
            "Malicious": reputation_result[
                "malicious"
            ],
            "Suspicious": reputation_result[
                "suspicious"
            ],
            "Total Engines": reputation_result[
                "total_engines"
            ],
            "Detection Ratio": risk_result[
                "detection_ratio"
            ],
            "Risk Score": risk_result[
                "risk_score"
            ],
            "Risk Level": risk_result[
                "risk_level"
            ],
            "Priority": priority,
            "Recommended Action": risk_result[
                "recommended_action"
            ],
            "Abuse Confidence": enrichment_result[
                "abuse_confidence"
            ],
            "Abuse Reports": enrichment_result[
                "abuse_reports"
            ],
            "Country": enrichment_result[
                "country"
            ],
            "ISP": enrichment_result[
                "isp"
            ],
            "Usage Type": enrichment_result[
                "usage_type"
            ],
            "OTX Pulses": enrichment_result[
                "otx_pulses"
            ],
            "OTX Threat Context": enrichment_result[
                "otx_threat_context"
            ],
            "Enrichment Status": enrichment_result[
                "enrichment_status"
            ]
        })

    # Phase 1-5:
    # Write original analysis report
    with open(
        output_file,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "IOC",
                "Type",
                "Normalized IOC",
                "Reputation",
                "Malicious",
                "Suspicious",
                "Total Engines",
                "Detection Ratio",
                "Risk Score",
                "Risk Level",
                "Priority",
                "Recommended Action",
                "Abuse Confidence",
                "Abuse Reports",
                "Country",
                "ISP",
                "Usage Type",
                "OTX Pulses",
                "OTX Threat Context",
                "Enrichment Status"
            ]
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    # Phase 6.1:
    # Create fresh investigation report
    investigation_results = (
        create_investigation_report(
            results
        )
    )

    # Phase 6.6:
    # Add analyst note to every investigation
    for result in investigation_results:
        result.setdefault(
            "Analyst Note",
            ""
        )

    # Phase 6.6:
    # Load previously saved investigation state
    saved_state = load_investigation_state(
        investigation_output_file
    )

    # Phase 6.6:
    # Restore investigation status and
    # analyst notes from previous runs
    investigation_results = (
        apply_saved_investigation_state(
            investigation_results,
            saved_state
        )
    )

    # Phase 6.6:
    # Save current investigation report
    save_investigation_results(
        investigation_results,
        investigation_output_file
    )

    # Phase 6.3:
    # Investigation summary
    investigation_summary = (
        generate_investigation_summary(
            investigation_results
        )
    )

    # Phase 6.5:
    # Generate human-readable SOC report
    soc_report = generate_soc_report(
        investigation_results,
        investigation_summary
    )

    with open(
        soc_report_output_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            soc_report
        )

    print(
        f"Processed {len(results)} IOCs."
    )

    print(
        f"Results saved to: {output_file}"
    )

    print(
        "SOC investigation report saved to: "
        f"{investigation_output_file}"
    )

    print(
        "SOC text report saved to: "
        f"{soc_report_output_file}"
    )

    print()

    # Phase 4:
    # Alert summary
    print("=== Alert Summary ===")

    print(
        f"P1 Critical: "
        f"{priority_counts['P1']}"
    )

    print(
        f"P2 High: "
        f"{priority_counts['P2']}"
    )

    print(
        f"P3 Medium: "
        f"{priority_counts['P3']}"
    )

    print(
        f"P4 Low/Unknown: "
        f"{priority_counts['P4']}"
    )

    # Phase 6.3:
    # Investigation summary
    print_investigation_summary(
        investigation_summary
    )

    # Phase 6.2 + Phase 6.6:
    # SOC investigation queue
    show_investigation_queue(
        investigation_results
    )


if __name__ == "__main__":
    main()