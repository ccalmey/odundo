# engine/scanner.py

import socket
from concurrent.futures import ThreadPoolExecutor

from analyzer import analyze_banner

# Common ports and services
COMMON_PORTS = {
    1: "TCPMUX",
    5: "RJE",
    7: "ECHO",
    9: "DISCARD",
    11: "SYSTAT",
    13: "DAYTIME",
    17: "QOTD",
    18: "MSP",
    19: "CHARGEN",
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    37: "TIME",
    42: "NAMESERVER",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    57: "MTP",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    69: "TFTP",
    70: "GOPHER",
    79: "FINGER",
    80: "HTTP",
    88: "KERBEROS",
    101: "HOSTNAME",
    102: "ISO-TSAP",
    107: "RTELNET",
    109: "POP2",
    110: "POP3",
    111: "SUNRPC",
    113: "IDENT",
    115: "SFTP",
    117: "UUCP-PATH",
    118: "SQLSERV",
    119: "NNTP",
    123: "NTP",
    135: "EPMAP",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    156: "SQL-SERVER",
    161: "SNMP",
    162: "SNMPTRAP",
    179: "BGP",
    194: "IRC",
    201: "AT-RTMP",
    202: "AT-NBP",
    204: "AT-ECHO",
    206: "AT-ZIS",
    318: "TSP",
    389: "LDAP",
    443: "HTTPS",
    444: "SNPP",
    445: "MICROSOFT-DS",
    464: "KERBEROS-IV",
    465: "SMTPS",
    500: "ISAKMP",
    512: "REXEC",
    513: "RLOGIN",
    514: "SYSLOG",
    515: "LPD",
    520: "RIP",
    521: "RIPNG",
    530: "RPC",
    531: "CONFERENCE",
    540: "UUCP",
    543: "KLOGIN",
    544: "KSHELL",
    546: "DHCPV6-CLIENT",
    547: "DHCPV6-SERVER",
    554: "RTSP",
    560: "RMONITOR",
    563: "NNTPS",
    587: "SMTP-SUBMISSION",
    593: "HTTP-RPC-EPMAP",
    631: "IPP",
    636: "LDAPS",
    646: "LDP",
    873: "RSYNC",
    989: "FTPS-DATA",
    990: "FTPS",
    992: "TELNETS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OPENVPN",
    1234: "VLC",
    1433: "MSSQL",
    1434: "MSSQL-M",
    1521: "ORACLE",
    1701: "L2TP",
    1723: "PPTP",
    1741: "CISCO-SYS",
    1812: "RADIUS-AUTH",
    1813: "RADIUS-ACCT",
    1900: "UPNP",
    2049: "NFS",
    2082: "CPANEL",
    2083: "CPANEL-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2181: "ZOOKEEPER",
    3000: "NODEJS-DEV",
    3128: "SQUID",
    3306: "MYSQL",
    3389: "RDP",
    3690: "SVN",
    4333: "MSQL",
    4500: "IPSEC-NAT-T",
    4848: "GLASSFISH",
    5000: "UPNP-DEV",
    5060: "SIP",
    5061: "SIPS",
    5222: "XMPP-CLIENT",
    5269: "XMPP-SERVER",
    5432: "POSTGRESQL",
    5554: "ADB",
    5631: "PCANYWHERE-DATA",
    5632: "PCANYWHERE-STAT",
    5672: "AMQP",
    5900: "VNC",
    5984: "COUCHDB",
    5985: "WMAN-HTTP",
    5986: "WMAN-HTTPS",
    6000: "X11",
    6379: "REDIS",
    6443: "KUBERNETES-API",
    7001: "WEBLOGIC",
    8000: "HTTP-ALT",
    8008: "HTTP-ALTERNATE",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    8888: "HTTP-DEV",
    9000: "SONARQUBE",
    9092: "KAFKA",
    9100: "PROMETHEUS-EXPORTER",
    9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH-NODE",
    9411: "ZIPKIN",
    9999: "URANIUM",
    11211: "MEMCACHED",
    27017: "MONGODB",
    27018: "MONGODB-SHARD",
    27019: "MONGODB-CONFIG",
}


# Resolve domain to IP
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[ODUNDO] Could not resolve target.")
        return None


# Security recommendations
def suggest_fix(port):
    fixes = {
        21: "Disable FTP or use SFTP instead.",
        22: "Use SSH keys and disable password login if possible.",
        23: "Disable Telnet immediately. Use SSH instead.",
        25: "Restrict SMTP relay access.",
        80: "Redirect HTTP traffic to HTTPS.",
        443: "Ensure TLS configuration is secure.",
        3306: "Restrict MySQL access to trusted IPs only.",
        3389: "Restrict RDP access and use VPN protection."
    }

    return fixes.get(
        port,
        "Restrict access using firewall rules or disable if unused."
    )


# Service-specific probing
def grab_banner(target, port, service):
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((target, port))

        # HTTP / HTTPS
        if service in ["HTTP", "HTTPS"]:
            sock.send(
                b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n"
            )

        # FTP
        elif service == "FTP":
            pass  # FTP sends banner automatically

        # SSH
        elif service == "SSH":
            pass  # SSH sends version automatically

        # SMTP
        elif service == "SMTP":
            pass  # SMTP sends greeting automatically

        # Generic probe
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode(errors="ignore").strip()

        sock.close()

        return banner if banner else "No banner"

    except:
        return "No banner"


# Scan individual port
def scan_port(target, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")

            banner = grab_banner(target, port, service)

            vulnerability = analyze_banner(banner)

            return {
        "port": port,
        "status": "open",
        "service": service,
        "banner": banner,
        "recommendation": suggest_fix(port),
        "vulnerability": vulnerability
                    }

    except:
        pass

    return None


# Scan target ports
def scan_target(target, ports, max_threads=100):
    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(scan_port, target, port)
            for port in ports
        ]

        for future in futures:
            result = future.result()

            if result:
                results.append(result)

    return results


# Main execution
if __name__ == "__main__":

    user_input = input(
        "Enter target IP or domain (e.g., 127.0.0.1 or scanme.nmap.org): "
    )

    target = resolve_target(user_input)

    if not target:
        exit()

    print(f"\n[ODUNDO] Scanning {target}...\n")

    ports_to_scan = range(1, 1025)

    results = scan_target(target, ports_to_scan)

    if results:
        for res in results:

            print(f"[+] Port {res['port']} OPEN")
            print(f"    Service : {res['service']}")
            print(f"    Banner  : {res['banner']}")
            print(f"    Fix     : {res['recommendation']}")

        if res['vulnerability']:

            vuln = res['vulnerability']

            print("    ⚠ VULNERABILITY DETECTED")
            print(f"    CVE        : {vuln['cve']}")
            print(f"    Severity   : {vuln['severity']}")
            print(f"    Description: {vuln['description']}")
            print(f"    Solution   : {vuln['fix']}")

        print("-" * 60)

    else:
        print("[ODUNDO] No open ports found.")