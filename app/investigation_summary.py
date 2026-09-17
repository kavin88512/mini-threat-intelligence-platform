def generate_investigation_summary(results):
    """
    Generate a summary of the current SOC investigation results.
    """

    risk_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }

    priority_counts = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0
    }

    enrichment_counts = {
        "SUCCESS": 0,
        "NOT_FOUND": 0,
        "NOT_SUPPORTED": 0,
        "ERROR": 0
    }

    status_counts = {}

    for result in results:

        # Risk summary
        risk_level = result["Risk Level"]

        if risk_level in risk_counts:
            risk_counts[risk_level] += 1

        # Priority summary
        priority = result["Priority"]

        if priority in priority_counts:
            priority_counts[priority] += 1

        # Enrichment summary
        enrichment_status = result["Enrichment Status"]

        if enrichment_status in enrichment_counts:
            enrichment_counts[enrichment_status] += 1

        # Investigation status summary
        investigation_status = result["Investigation Status"]

        status_counts[investigation_status] = (
            status_counts.get(investigation_status, 0) + 1
        )

    # Find highest-priority IOC
    highest_priority_ioc = None

    priority_order = {
        "P1": 1,
        "P2": 2,
        "P3": 3,
        "P4": 4
    }

    for result in results:
        priority = result["Priority"]

        if priority not in priority_order:
            continue

        if highest_priority_ioc is None:
            highest_priority_ioc = result
            continue

        current_priority = priority_order[priority]
        highest_priority = priority_order[
            highest_priority_ioc["Priority"]
        ]

        if current_priority < highest_priority:
            highest_priority_ioc = result

    if highest_priority_ioc:
        highest_priority_details = {
            "IOC": highest_priority_ioc["IOC"],
            "Priority": highest_priority_ioc["Priority"],
            "Risk Level": highest_priority_ioc["Risk Level"]
        }
    else:
        highest_priority_details = None

    return {
        "total_iocs": len(results),
        "risk_counts": risk_counts,
        "priority_counts": priority_counts,
        "enrichment_counts": enrichment_counts,
        "status_counts": status_counts,
        "highest_priority_ioc": highest_priority_details
    }


def print_investigation_summary(summary):
    """
    Display the investigation summary in the terminal.
    """

    print()
    print("=== Investigation Summary ===")

    print()
    print(f"Total IOCs: {summary['total_iocs']}")

    print()
    print("Risk Summary:")
    print(f"  Critical: {summary['risk_counts']['CRITICAL']}")
    print(f"  High:     {summary['risk_counts']['HIGH']}")
    print(f"  Medium:   {summary['risk_counts']['MEDIUM']}")
    print(f"  Low:      {summary['risk_counts']['LOW']}")
    print(f"  Unknown:  {summary['risk_counts']['UNKNOWN']}")

    print()
    print("Priority Summary:")
    print(f"  P1: {summary['priority_counts']['P1']}")
    print(f"  P2: {summary['priority_counts']['P2']}")
    print(f"  P3: {summary['priority_counts']['P3']}")
    print(f"  P4: {summary['priority_counts']['P4']}")

    print()
    print("Enrichment Summary:")
    print(
        f"  Successful:     "
        f"{summary['enrichment_counts']['SUCCESS']}"
    )
    print(
        f"  Not Found:      "
        f"{summary['enrichment_counts']['NOT_FOUND']}"
    )
    print(
        f"  Not Supported:  "
        f"{summary['enrichment_counts']['NOT_SUPPORTED']}"
    )
    print(
        f"  Errors:         "
        f"{summary['enrichment_counts']['ERROR']}"
    )

    print()
    print("Investigation Status:")

    if summary["status_counts"]:
        for status, count in summary["status_counts"].items():
            print(f"  {status}: {count}")
    else:
        print("  No investigation records.")

    print()
    print("Highest Priority IOC:")

    if summary["highest_priority_ioc"]:
        print(
            f"  IOC: "
            f"{summary['highest_priority_ioc']['IOC']}"
        )
        print(
            f"  Priority: "
            f"{summary['highest_priority_ioc']['Priority']}"
        )
        print(
            f"  Risk Level: "
            f"{summary['highest_priority_ioc']['Risk Level']}"
        )
    else:
        print("  No priority information available.")