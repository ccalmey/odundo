# engine/analyzer.py

import re

# Simple local CVE intelligence database
CVE_DATABASE = {
    "Apache/2.4.49": {
        "cve": "CVE-2021-41773",
        "severity": "CRITICAL",
        "description": "Path traversal and remote code execution vulnerability.",
        "fix": "Upgrade Apache to version 2.4.51 or later."
    },

    "OpenSSH_7.2": {
        "cve": "CVE-2016-0777",
        "severity": "HIGH",
        "description": "Information leak vulnerability in OpenSSH roaming.",
        "fix": "Upgrade OpenSSH and disable roaming."
    },

    "vsFTPd 2.3.4": {
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "description": "Backdoor command execution vulnerability.",
        "fix": "Upgrade vsFTPd immediately."
    }
}


def analyze_banner(banner):
    """
    Analyze banner for known vulnerable versions
    """

    if not banner or banner == "No banner":
        return None

    for software, vuln_data in CVE_DATABASE.items():

        pattern = re.escape(software)

        if re.search(pattern, banner, re.IGNORECASE):
            return {
                "software": software,
                "cve": vuln_data["cve"],
                "severity": vuln_data["severity"],
                "description": vuln_data["description"],
                "fix": vuln_data["fix"]
            }

    return None