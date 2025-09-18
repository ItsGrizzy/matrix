// Comprehensive Nmap Commands Database
const NMAP_COMMANDS = {
    "Basic Scanning": [
        {
            "id": 1,
            "name": "Basic Host Discovery",
            "command": "nmap {ip}",
            "description": "Basic TCP port scan on common ports",
            "category": "Discovery"
        },
        {
            "id": 2,
            "name": "Fast Scan",
            "command": "nmap -F {ip}",
            "description": "Fast scan of the most common 100 ports",
            "category": "Discovery"
        },
        {
            "id": 3,
            "name": "All Ports Scan",
            "command": "nmap -p- {ip}",
            "description": "Scan all 65535 TCP ports",
            "category": "Discovery"
        },
        {
            "id": 4,
            "name": "Top Ports Scan",
            "command": "nmap --top-ports 1000 {ip}",
            "description": "Scan the top 1000 most common ports",
            "category": "Discovery"
        },
        {
            "id": 5,
            "name": "Specific Ports",
            "command": "nmap -p 22,80,443,3389 {ip}",
            "description": "Scan specific ports (SSH, HTTP, HTTPS, RDP)",
            "category": "Discovery"
        },
        {
            "id": 6,
            "name": "Port Range Scan",
            "command": "nmap -p 1-1000 {ip}",
            "description": "Scan a range of ports (1-1000)",
            "category": "Discovery"
        },
        {
            "id": 7,
            "name": "UDP Scan",
            "command": "nmap -sU {ip}",
            "description": "UDP port scan (slower but important)",
            "category": "Discovery"
        },
        {
            "id": 8,
            "name": "TCP Connect Scan",
            "command": "nmap -sT {ip}",
            "description": "TCP connect scan (more reliable)",
            "category": "Discovery"
        },
        {
            "id": 9,
            "name": "SYN Scan",
            "command": "nmap -sS {ip}",
            "description": "TCP SYN scan (stealth scan, default)",
            "category": "Discovery"
        },
        {
            "id": 10,
            "name": "Network Range Scan",
            "command": "nmap {ip}/24",
            "description": "Scan entire network subnet",
            "category": "Discovery"
        }
    ],
    "Advanced Scanning": [
        {
            "id": 11,
            "name": "Aggressive Scan",
            "command": "nmap -A {ip}",
            "description": "Aggressive scan (OS detection, version detection, script scanning)",
            "category": "Enumeration"
        },
        {
            "id": 12,
            "name": "Service Version Detection",
            "command": "nmap -sV {ip}",
            "description": "Detect service versions on open ports",
            "category": "Enumeration"
        },
        {
            "id": 13,
            "name": "OS Detection",
            "command": "nmap -O {ip}",
            "description": "Operating system detection",
            "category": "Enumeration"
        },
        {
            "id": 14,
            "name": "Script Scan",
            "command": "nmap -sC {ip}",
            "description": "Run default NSE scripts",
            "category": "Enumeration"
        },
        {
            "id": 15,
            "name": "Vulnerability Scan",
            "command": "nmap --script vuln {ip}",
            "description": "Run vulnerability detection scripts",
            "category": "Vulnerability Assessment"
        },
        {
            "id": 16,
            "name": "HTTP Enumeration",
            "command": "nmap --script http-enum {ip}",
            "description": "Enumerate HTTP directories and files",
            "category": "Web Application"
        },
        {
            "id": 17,
            "name": "SMB Enumeration",
            "command": "nmap --script smb-enum-* {ip}",
            "description": "Enumerate SMB shares and information",
            "category": "SMB"
        },
        {
            "id": 18,
            "name": "DNS Enumeration",
            "command": "nmap --script dns-brute {ip}",
            "description": "DNS subdomain brute force",
            "category": "DNS"
        },
        {
            "id": 19,
            "name": "SSL/TLS Analysis",
            "command": "nmap --script ssl-* {ip}",
            "description": "Analyze SSL/TLS configuration",
            "category": "SSL/TLS"
        },
        {
            "id": 20,
            "name": "FTP Enumeration",
            "command": "nmap --script ftp-* {ip}",
            "description": "FTP service enumeration",
            "category": "FTP"
        }
    ],
    "Stealth & Evasion": [
        {
            "id": 21,
            "name": "Stealth Scan",
            "command": "nmap -sS -T2 {ip}",
            "description": "Slow stealth scan to avoid detection",
            "category": "Evasion"
        },
        {
            "id": 22,
            "name": "Decoy Scan",
            "command": "nmap -D RND:10 {ip}",
            "description": "Use random decoy IP addresses",
            "category": "Evasion"
        },
        {
            "id": 23,
            "name": "Fragment Packets",
            "command": "nmap -f {ip}",
            "description": "Fragment packets to evade firewalls",
            "category": "Evasion"
        },
        {
            "id": 24,
            "name": "Spoof Source IP",
            "command": "nmap -S {spoofed_ip} {ip}",
            "description": "Spoof source IP address",
            "category": "Evasion"
        },
        {
            "id": 25,
            "name": "Idle Scan",
            "command": "nmap -sI {zombie_ip} {ip}",
            "description": "Idle scan using zombie host",
            "category": "Evasion"
        },
        {
            "id": 26,
            "name": "Timing Template (Slow)",
            "command": "nmap -T1 {ip}",
            "description": "Very slow scan for IDS evasion",
            "category": "Evasion"
        },
        {
            "id": 27,
            "name": "Random Host Order",
            "command": "nmap --randomize-hosts {ip}/24",
            "description": "Randomize host scanning order",
            "category": "Evasion"
        },
        {
            "id": 28,
            "name": "Source Port Spoofing",
            "command": "nmap --source-port 53 {ip}",
            "description": "Use specific source port (DNS)",
            "category": "Evasion"
        }
    ],
    "Web Application Testing": [
        {
            "id": 29,
            "name": "HTTP Methods",
            "command": "nmap --script http-methods {ip}",
            "description": "Discover supported HTTP methods",
            "category": "Web Application"
        },
        {
            "id": 30,
            "name": "HTTP Headers",
            "command": "nmap --script http-headers {ip}",
            "description": "Analyze HTTP response headers",
            "category": "Web Application"
        },
        {
            "id": 31,
            "name": "Web Crawling",
            "command": "nmap --script http-spider {ip}",
            "description": "Spider web application for directories",
            "category": "Web Application"
        },
        {
            "id": 32,
            "name": "SQL Injection Test",
            "command": "nmap --script http-sql-injection {ip}",
            "description": "Test for SQL injection vulnerabilities",
            "category": "Web Application"
        },
        {
            "id": 33,
            "name": "XSS Detection",
            "command": "nmap --script http-stored-xss,http-xssed {ip}",
            "description": "Test for Cross-Site Scripting (XSS)",
            "category": "Web Application"
        },
        {
            "id": 34,
            "name": "Web Technologies",
            "command": "nmap --script http-waf-detect,http-waf-fingerprint {ip}",
            "description": "Detect web technologies and WAF",
            "category": "Web Application"
        },
        {
            "id": 35,
            "name": "WordPress Scan",
            "command": "nmap --script http-wordpress-* {ip}",
            "description": "WordPress-specific security tests",
            "category": "Web Application"
        }
    ],
    "Database Testing": [
        {
            "id": 36,
            "name": "MySQL Enumeration",
            "command": "nmap --script mysql-* {ip}",
            "description": "MySQL database enumeration",
            "category": "Database"
        },
        {
            "id": 37,
            "name": "MSSQL Enumeration",
            "command": "nmap --script ms-sql-* {ip}",
            "description": "Microsoft SQL Server enumeration",
            "category": "Database"
        },
        {
            "id": 38,
            "name": "MongoDB Enumeration",
            "command": "nmap --script mongodb-* {ip}",
            "description": "MongoDB database enumeration",
            "category": "Database"
        },
        {
            "id": 39,
            "name": "Oracle Enumeration",
            "command": "nmap --script oracle-* {ip}",
            "description": "Oracle database enumeration",
            "category": "Database"
        },
        {
            "id": 40,
            "name": "PostgreSQL Enumeration",
            "command": "nmap --script pgsql-brute {ip}",
            "description": "PostgreSQL brute force attack",
            "category": "Database"
        }
    ],
    "Network Discovery": [
        {
            "id": 41,
            "name": "Ping Sweep",
            "command": "nmap -sn {ip}/24",
            "description": "Ping sweep to discover live hosts",
            "category": "Discovery"
        },
        {
            "id": 42,
            "name": "ARP Scan",
            "command": "nmap -PR {ip}/24",
            "description": "ARP ping scan for local network",
            "category": "Discovery"
        },
        {
            "id": 43,
            "name": "DNS Resolution",
            "command": "nmap -sL {ip}/24",
            "description": "List scan with DNS resolution",
            "category": "Discovery"
        },
        {
            "id": 44,
            "name": "Traceroute",
            "command": "nmap --traceroute {ip}",
            "description": "Perform traceroute to target",
            "category": "Discovery"
        },
        {
            "id": 45,
            "name": "No DNS Resolution",
            "command": "nmap -n {ip}",
            "description": "Skip DNS resolution for faster scanning",
            "category": "Performance"
        },
        {
            "id": 46,
            "name": "IPv6 Scan",
            "command": "nmap -6 {ipv6}",
            "description": "IPv6 network scanning",
            "category": "Discovery"
        }
    ],
    "Performance & Output": [
        {
            "id": 47,
            "name": "Fast Timing",
            "command": "nmap -T4 {ip}",
            "description": "Fast scan timing template",
            "category": "Performance"
        },
        {
            "id": 48,
            "name": "Parallel Scanning",
            "command": "nmap --min-parallelism 100 {ip}",
            "description": "Increase parallel scan processes",
            "category": "Performance"
        },
        {
            "id": 49,
            "name": "XML Output",
            "command": "nmap -oX scan_results.xml {ip}",
            "description": "Save results in XML format",
            "category": "Output"
        },
        {
            "id": 50,
            "name": "Greppable Output",
            "command": "nmap -oG scan_results.gnmap {ip}",
            "description": "Save results in greppable format",
            "category": "Output"
        },
        {
            "id": 51,
            "name": "All Formats Output",
            "command": "nmap -oA scan_results {ip}",
            "description": "Save in all output formats",
            "category": "Output"
        },
        {
            "id": 52,
            "name": "Verbose Output",
            "command": "nmap -v {ip}",
            "description": "Verbose output for detailed information",
            "category": "Output"
        }
    ]
};