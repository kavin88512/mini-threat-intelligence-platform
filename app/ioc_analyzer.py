import ipaddress
import re


def identify_ioc(ioc):
    ioc = ioc.strip()

    # Check if IOC is an IP address
    try:
        ipaddress.ip_address(ioc)
        return "IP Address"
    except ValueError:
        pass

    # Check if IOC is a URL
    if ioc.startswith(("http://", "https://")):
        return "URL"

    # Check if IOC is a domain
    domain_pattern = r"^(?=.{1,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    if re.match(domain_pattern, ioc):
        return "Domain"

    # Check if IOC is a file hash
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "MD5 Hash"

    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "SHA-1 Hash"

    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "SHA-256 Hash"

    return "Unknown"


def normalize_ioc(ioc, ioc_type):
    ioc = ioc.strip()

    if ioc_type == "Domain":
        return ioc.lower()

    if "Hash" in ioc_type:
        return ioc.lower()

    return ioc