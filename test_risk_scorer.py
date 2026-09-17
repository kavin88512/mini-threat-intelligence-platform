from app.risk_scorer import calculate_risk


test_cases = [
    {
        "name": "Clean IOC",
        "malicious": 0,
        "suspicious": 0,
        "total_engines": 70
    },
    {
        "name": "Low Risk IOC",
        "malicious": 2,
        "suspicious": 1,
        "total_engines": 70
    },
    {
        "name": "Medium Risk IOC",
        "malicious": 20,
        "suspicious": 5,
        "total_engines": 70
    },
    {
        "name": "High Risk IOC",
        "malicious": 40,
        "suspicious": 5,
        "total_engines": 70
    },
    {
        "name": "Critical Risk IOC",
        "malicious": 66,
        "suspicious": 0,
        "total_engines": 70
    }
]


for test in test_cases:
    result = calculate_risk(
        test["malicious"],
        test["suspicious"],
        test["total_engines"]
    )

    print(f"\n{test['name']}")
    print(f"Detection Ratio: {result['detection_ratio']}%")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Recommended Action: {result['recommended_action']}")


print("\nUnknown IOC")

result = calculate_risk(
    malicious=0,
    suspicious=0,
    total_engines=0,
    reputation="not_found"
)

print(f"Detection Ratio: {result['detection_ratio']}%")
print(f"Risk Score: {result['risk_score']}")
print(f"Risk Level: {result['risk_level']}")
print(f"Recommended Action: {result['recommended_action']}")