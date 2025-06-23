port_vuln_db = {
    21: {
        "service": "FTP",
        "attack": "Anonymous login, sniffing, brute force",
        "precaution": "Disable anonymous access, use SFTP or FTPS, limit IP access"
    },
    22: {
        "service": "SSH",
        "attack": "Brute force, user enumeration, outdated ciphers",
        "precaution": "Use key-based auth, disable root login, enable 2FA, use fail2ban"
    },
    23: {
        "service": "Telnet",
        "attack": "Cleartext passwords, session hijacking",
        "precaution": "Avoid using Telnet; use SSH instead"
    },
    25: {
        "service": "SMTP",
        "attack": "Email spoofing, open relay abuse",
        "precaution": "Enable authentication, configure SPF/DKIM/DMARC"
    },
    53: {
        "service": "DNS",
        "attack": "Cache poisoning, amplification attacks",
        "precaution": "Use DNSSEC, rate limiting, restrict recursion"
    },
    80: {
        "service": "HTTP",
        "attack": "XSS, SQLi, MITM",
        "precaution": "Use HTTPS, sanitize inputs, use WAF"
    },
    110: {
        "service": "POP3",
        "attack": "Cleartext credentials, spoofing",
        "precaution": "Use POP3S (SSL), disable plaintext auth"
    },
    143: {
        "service": "IMAP",
        "attack": "Credential theft, buffer overflows",
        "precaution": "Use IMAPS, patch mail server"
    },
    443: {
        "service": "HTTPS",
        "attack": "SSL vulnerabilities, Heartbleed",
        "precaution": "Use strong TLS config, disable weak ciphers"
    },
    3306: {
        "service": "MySQL",
        "attack": "SQL injection, weak DB auth",
        "precaution": "Use strong creds, limit IPs, keep DB updated"
    },
    3389: {
        "service": "RDP",
        "attack": "Brute force, BlueKeep (CVE-2019-0708)",
        "precaution": "Use VPN, enable NLA, patch system, use 2FA"
    },
    8080: {
        "service": "HTTP Proxy / Web",
        "attack": "Proxy misconfig, open admin panels",
        "precaution": "Restrict access, require auth, patch services"
    },
        20: {
        "service": "FTP (Data)",
        "attack": "Data sniffing",
        "precaution": "Use secure file transfer protocols like SFTP or FTPS"
    },
    67: {
        "service": "DHCP Server",
        "attack": "Rogue DHCP server attacks, denial of service",
        "precaution": "Use MAC filtering, switch port security, DHCP snooping"
    },
    68: {
        "service": "DHCP Client",
        "attack": "Fake responses from rogue DHCP servers",
        "precaution": "Restrict DHCP access to trusted hosts only"
    },
    69: {
        "service": "TFTP",
        "attack": "Unauthorized file access, lack of authentication",
        "precaution": "Avoid TFTP; use SCP/SFTP with authentication"
    },
    111: {
        "service": "RPCbind / portmapper",
        "attack": "Info disclosure, DoS via NFS",
        "precaution": "Restrict access to trusted IPs, firewall unused RPC services"
    },
    135: {
        "service": "MS RPC",
        "attack": "DCE/RPC exploitation, lateral movement",
        "precaution": "Block externally, patch Windows regularly"
    },
    139: {
        "service": "NetBIOS Session Service",
        "attack": "SMB exploits, NetBIOS name poisoning",
        "precaution": "Disable NetBIOS if not needed, use firewall rules"
    },
    161: {
        "service": "SNMP",
        "attack": "Community string brute force, info disclosure",
        "precaution": "Use SNMPv3, strong community strings, limit access"
    },
    162: {
        "service": "SNMP Trap",
        "attack": "Trap flooding, spoofing",
        "precaution": "Restrict SNMP traps to trusted managers"
    },
    445: {
        "service": "Microsoft-DS / SMB",
        "attack": "EternalBlue, SMB relay, ransomware spread",
        "precaution": "Disable SMBv1, patch OS, use host firewalls"
    },
    514: {
        "service": "Syslog",
        "attack": "Log injection, data tampering",
        "precaution": "Encrypt logs in transit (TLS), restrict source IPs"
    },
    587: {
        "service": "SMTP (submission)",
        "attack": "Email injection, relay abuse",
        "precaution": "Require SMTP auth, enable STARTTLS"
    },
    631: {
        "service": "IPP (CUPS Printing)",
        "attack": "Printer hijacking, info disclosure",
        "precaution": "Restrict printing services to local network"
    },
    8080: {
        "service": "HTTP Alternate / Proxy",
        "attack": "Open proxy abuse, admin panels exposed",
        "precaution": "Authenticate access, limit by IP, patch apps"
    },
    8443: {
        "service": "HTTPS (alt)",
        "attack": "SSL misconfig, outdated TLS",
        "precaution": "Use TLS 1.2/1.3, strong ciphers, renew certs"
    },
    8888: {
        "service": "Web service / proxy",
        "attack": "Open dashboard, unauth APIs",
        "precaution": "Set admin passwords, restrict access, disable unused ports"
    },
    9200: {
        "service": "Elasticsearch",
        "attack": "Unauth access, data leakage",
        "precaution": "Enable auth, firewall the port, disable remote shell access"
    },
    11211: {
        "service": "Memcached",
        "attack": "Reflection DDoS, data dump",
        "precaution": "Bind to localhost, use firewall, disable UDP if unused"
    },
        1433: {
        "service": "Microsoft SQL Server",
        "attack": "SQL injection, weak authentication, remote code execution",
        "precaution": "Use strong credentials, restrict access, keep server patched"
    },
    1521: {
        "service": "Oracle DB",
        "attack": "SID brute force, CVE-based RCE",
        "precaution": "Limit external access, monitor DB logs, patch vulnerabilities"
    },
    1900: {
        "service": "UPnP",
        "attack": "SSDP amplification DDoS, information disclosure",
        "precaution": "Disable UPnP on routers, block external SSDP traffic"
    },
    2483: {
        "service": "Oracle DB Listener TCP",
        "attack": "Listener DoS, SID brute force",
        "precaution": "Use listener password, patch regularly, restrict listener IPs"
    },
    3128: {
        "service": "Squid Proxy",
        "attack": "Open proxy abuse, cache poisoning",
        "precaution": "Restrict access, configure ACLs, enable auth"
    },
    3300: {
        "service": "SAP Dispatcher",
        "attack": "Code injection, buffer overflow",
        "precaution": "Patch SAP, isolate dispatcher, monitor logs"
    },
    5000: {
        "service": "UPnP / Docker REST API",
        "attack": "Remote command execution, service discovery abuse",
        "precaution": "Disable unused APIs, firewall internal services"
    },
    5432: {
        "service": "PostgreSQL",
        "attack": "Auth bypass, SQL injection, CVEs",
        "precaution": "Use SSL, strong auth, patch PostgreSQL"
    },
    6379: {
        "service": "Redis",
        "attack": "Unauth access, RCE via module loading",
        "precaution": "Bind to localhost, enable auth, use firewall"
    },
    7001: {
        "service": "WebLogic Server",
        "attack": "Deserialization RCE (e.g. CVE-2020-14882)",
        "precaution": "Apply security patches, restrict access, enable auth"
    },
    8000: {
        "service": "Common Dev Server (Python/Node)",
        "attack": "Directory traversal, code execution",
        "precaution": "Do not expose dev servers to public, use firewall"
    },
    9200: {
        "service": "Elasticsearch",
        "attack": "Data exfiltration, RCE, unauth access",
        "precaution": "Enable X-Pack security, bind to localhost, limit APIs"
    },
    11211: {
        "service": "Memcached",
        "attack": "Reflection DDoS, info disclosure",
        "precaution": "Disable UDP, bind to localhost, firewall access"
    },
    27017: {
        "service": "MongoDB",
        "attack": "Unauth access, data leakage",
        "precaution": "Enable auth, bind to localhost, use TLS"
    },
    3389: {
        "service": "Remote Desktop Protocol",
        "attack": "Brute force, CVE-2019-0708 (BlueKeep)",
        "precaution": "Enable NLA, use VPN, restrict IPs, apply patches"
    },
        81: {
        "service": "Alternate HTTP",
        "attack": "Unsecured web interfaces, default credentials",
        "precaution": "Use HTTPS, change default creds, restrict access"
    },
    135: {
        "service": "Microsoft RPC",
        "attack": "DCE/RPC exploitation, lateral movement",
        "precaution": "Block externally, patch Windows, restrict access"
    },
    137: {
        "service": "NetBIOS Name Service",
        "attack": "Name poisoning, info disclosure",
        "precaution": "Disable NetBIOS if unused, filter ports 137-139"
    },
    138: {
        "service": "NetBIOS Datagram Service",
        "attack": "Data leakage, broadcast abuse",
        "precaution": "Block on perimeter, use internal segmentation"
    },
    139: {
        "service": "NetBIOS Session Service",
        "attack": "SMB exploitation, enumeration",
        "precaution": "Disable SMBv1, use SMB signing, block externally"
    },
    161: {
        "service": "SNMP",
        "attack": "Brute force community strings, info leakage",
        "precaution": "Use SNMPv3, limit IPs, change community strings"
    },
    162: {
        "service": "SNMP Trap",
        "attack": "Spoofed traps, trap flooding",
        "precaution": "Filter sources, enable auth for traps"
    },
    179: {
        "service": "BGP",
        "attack": "Route hijacking, session reset",
        "precaution": "Enable MD5 auth, filter peerings, monitor routes"
    },
    389: {
        "service": "LDAP",
        "attack": "Info disclosure, LDAP injection",
        "precaution": "Use LDAPS, validate input, restrict anonymous binds"
    },
    427: {
        "service": "SLP (Service Location Protocol)",
        "attack": "Reflection DDoS, service spoofing",
        "precaution": "Disable SLP on endpoints, firewall port"
    },
    500: {
        "service": "ISAKMP / IKE (VPN)",
        "attack": "Aggressive mode leaks, VPN fingerprinting",
        "precaution": "Use strong PSK, avoid aggressive mode, patch VPN software"
    },
    514: {
        "service": "Syslog",
        "attack": "Log spoofing, injection",
        "precaution": "Use TCP with TLS, restrict sources"
    },
    515: {
        "service": "Line Printer Daemon (LPD)",
        "attack": "Printer misuse, DoS",
        "precaution": "Use secure printing, disable LPD if unused"
    },
    873: {
        "service": "rsync",
        "attack": "Directory listing, file leaks",
        "precaution": "Restrict to internal IPs, disable anonymous"
    },
    1900: {
        "service": "UPnP SSDP",
        "attack": "SSDP amplification, service enumeration",
        "precaution": "Block externally, disable UPnP"
    },
    49152: {
        "service": "Windows RPC Dynamic Port",
        "attack": "Service exposure, remote execution",
        "precaution": "Restrict dynamic port ranges, firewall access"
    },
    50070: {
        "service": "Hadoop Web UI",
        "attack": "Unauth admin panel, info disclosure",
        "precaution": "Restrict web access, use strong auth"
    },
        5000: {
        "service": "Docker API / UPnP / Dev server",
        "attack": "Remote code execution, exposed dev tools",
        "precaution": "Restrict access, disable Docker remote API, never expose dev servers"
    },
    5900: {
        "service": "VNC",
        "attack": "Unauthenticated access, brute-force, screen hijack",
        "precaution": "Use strong passwords, enable encryption, restrict IPs"
    },
    7000: {
        "service": "Cisco MGCP / Oracle Admin / Custom App",
        "attack": "Custom exploits, weak auth",
        "precaution": "Change default configs, monitor usage, apply vendor-specific patches"
    },
    8008: {
        "service": "HTTP Alternate / IoT UI",
        "attack": "Unprotected web panels, device takeover",
        "precaution": "Restrict access, enforce authentication"
    },
    8081: {
        "service": "HTTP Proxy / Jenkins / Dev Tools",
        "attack": "Dashboard exposure, RCE",
        "precaution": "Disable unused services, use reverse proxy with auth"
    },
    10000: {
        "service": "Webmin",
        "attack": "Privileged RCE, weak auth",
        "precaution": "Update Webmin, use SSL, restrict access"
    },
    27017: {
        "service": "MongoDB",
        "attack": "Unauth access, data exfiltration",
        "precaution": "Bind to localhost, enable auth, use firewalls"
    },
    4444: {
        "service": "Metasploit / Custom Shell",
        "attack": "Backdoor, listener exposure",
        "precaution": "Close when unused, monitor traffic, secure configs"
    },
    5800: {
        "service": "VNC Web Access",
        "attack": "Session hijacking via browser, info leak",
        "precaution": "Use HTTPS, set strong passwords, limit access"
    },
    6666: {
        "service": "IRC / Malware Ports",
        "attack": "Botnet control, DoS relay",
        "precaution": "Block port unless needed, monitor unusual traffic"
    },
    8089: {
        "service": "Splunk Web",
        "attack": "Data leakage, dashboard access",
        "precaution": "Enforce login, restrict IPs, monitor access logs"
    },
    49152: {
        "service": "Windows RPC Dynamic",
        "attack": "Service enumeration, RCE",
        "precaution": "Limit dynamic port ranges, firewall access"
    },
    5601: {
        "service": "Kibana",
        "attack": "Unauth access, index manipulation",
        "precaution": "Use reverse proxy, enable login, patch frequently"
    },
    15672: {
        "service": "RabbitMQ Management",
        "attack": "Web UI abuse, credential reuse",
        "precaution": "Disable public access, set strong creds"
    }
    
}
