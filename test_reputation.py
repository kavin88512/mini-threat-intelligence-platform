from app.reputation_checker import check_reputation

test_iocs = [
    "8.8.8.8",
    "example.com",
    "https://example.com",
    "44d88612fea8a8f36de82e1278abb02f"
]

for ioc in test_iocs:
    result = check_reputation(ioc)
    print(result)