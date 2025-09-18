# 🚀 CyberCommand Matrix - Advanced Cybersecurity Command Generator

A comprehensive, real-time command generator for cybersecurity professionals, penetration testers, red teamers, and CTF players. This tool provides instant access to over **300+ cybersecurity commands** across multiple tools and platforms.

![CyberCommand Matrix](https://img.shields.io/badge/Commands-300+-blue?style=for-the-badge) ![Tools](https://img.shields.io/badge/Tools-12+-green?style=for-the-badge) ![Real--Time](https://img.shields.io/badge/Updates-Real--Time-orange?style=for-the-badge)

## ✨ Key Features

### 🔄 **Real-Time Command Generation**
- **Instant Updates**: Commands automatically update as you type
- **Smart Placeholder Replacement**: Intelligent handling of IPs, usernames, passwords
- **Null Session Support**: Automatically generates null session commands when credentials are empty
- **Live Preview**: See exactly what will be executed before copying

### 🛠️ **Comprehensive Tool Coverage**
- **NetExec**: 50+ commands for SMB, LDAP, WinRM, MSSQL, SSH protocols
- **Nmap**: 52+ scanning, enumeration, and script commands
- **Web Application Testing**: 45+ commands for SQLi, XSS, directory traversal
- **Reconnaissance**: 40+ OSINT and network discovery commands
- **Exploitation**: 25+ Metasploit, payload generation, privilege escalation
- **Password Cracking**: 30+ hashcat, john, hydra, and brute force commands
- **Windows Tools**: 35+ Active Directory, PowerShell, privilege escalation
- **Linux Tools**: 28+ system enumeration, file operations, privilege escalation
- **Mobile Testing**: 20+ Android and iOS security testing commands
- **Cloud Security**: 15+ AWS and Azure assessment commands
- **Digital Forensics**: 22+ disk analysis, memory forensics, file recovery

### 🎯 **Modern Interface**
- **Dark Theme**: Optimized for long penetration testing sessions
- **Horizontal Scrolling Tabs**: Easy navigation between tool categories
- **Search Functionality**: Quickly find specific commands
- **Category Filtering**: Organize commands by attack vectors
- **Responsive Design**: Works on desktop, tablet, and mobile devices

### 💡 **Smart Features**
- **Keyboard Shortcuts**: Ctrl+K to search, Escape to close modals
- **Export Functionality**: Save filtered commands as JSON
- **Session Persistence**: Auto-saves your inputs and preferences
- **Copy with One Click**: Instantly copy commands to clipboard
- **Help System**: Built-in documentation and usage examples

## 🚀 Quick Start

### 1. Clone or Download
```bash
git clone https://github.com/yourusername/cybercommand-matrix.git
cd cybercommand-matrix
```

### 2. Serve Locally
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx http-server

# Using PHP
php -S localhost:8000
```

### 3. Open in Browser
Navigate to `http://localhost:8000` and start generating commands!

## 📁 Project Structure

```
cybercommand-matrix/
├── index.html              # Main application interface
├── styles.css              # Enhanced dark theme styles
├── app.js                   # Core application logic
├── netexec.js              # NetExec command database
├── nmap.js                 # Nmap command database
├── web.js                  # Web application testing commands
├── recon.js                # Reconnaissance commands + others
├── additional-tools.js     # Windows, Linux, Mobile, Cloud, Forensics
├── package.json            # NPM configuration
├── .gitignore             # Git ignore rules
└── README.md              # This documentation
```

## 🎯 Usage Guide

### **Step 1: Global Configuration**
1. Enter your target IP address, domain, or CIDR range
2. Add username and password (optional - leave empty for null sessions)
3. Specify domain if testing Active Directory environments

### **Step 2: Select Tool Category**
- Use the horizontal scrolling toolbar to navigate between tools
- Choose from NetExec, Nmap, Web Testing, Recon, and more
- See command counts for each category

### **Step 3: Filter and Search**
- Use category filters to focus on specific attack vectors
- Search for commands by name, description, or category
- Commands update in real-time as you modify inputs

### **Step 4: Copy and Execute**
- Click any command card to copy it to clipboard
- Commands are automatically customized with your inputs
- Use the export feature to save filtered command sets

## 🔧 Advanced Features

### **Real-Time Command Processing**
```javascript
// Input: IP = "192.168.1.100", Username = "admin", Password = ""
// Original: netexec smb {ip} -u {username} -p {password}
// Generated: netexec smb 192.168.1.100 -u admin -p ''
```

### **Smart Null Session Handling**
When username and password are empty, the tool automatically generates appropriate null session commands:
```bash
netexec smb 192.168.1.100 -u '' -p ''
```

### **Keyboard Shortcuts**
- `Ctrl + K`: Focus search box
- `Escape`: Close modals and overlays
- `Click`: Copy command instantly

### **Export Capabilities**
Export filtered commands as JSON with metadata:
```json
{
  "timestamp": "2025-01-01T12:00:00.000Z",
  "tool": "netexec",
  "globalInputs": {...},
  "commands": [...],
  "totalCommands": 25
}
```

## 🛡️ Security & Privacy

- **Client-Side Only**: All processing happens in your browser
- **No Data Transmission**: Your inputs never leave your device
- **Local Storage**: Session data stored locally only
- **HTTPS Recommended**: Use HTTPS when deploying for added security

## 🎨 Customization

### **Adding New Commands**
1. Edit the appropriate `.js` file (e.g., `netexec.js`)
2. Add commands following the existing structure:
```javascript
{
    "id": 99,
    "name": "Custom Command",
    "command": "tool {ip} -u {username} -p {password}",
    "description": "Description of what this command does",
    "category": "Custom Category"
}
```

### **Adding New Tool Categories**
1. Create a new command database file (e.g., `mytool.js`)
2. Add the tool to `app.js` in the `toolDatabases` object
3. Update the HTML to include the new tool button

### **Styling**
- Modify CSS variables in `styles.css` for color schemes
- Update `--accent-blue`, `--bg-primary`, etc. for theme changes
- All styles are responsive and mobile-friendly

## 🚀 Deployment Options

### **GitHub Pages**
1. Upload files to GitHub repository
2. Enable GitHub Pages in repository settings
3. Access via `https://yourusername.github.io/repository-name`

### **Netlify/Vercel**
1. Drag and drop project folder
2. Automatic deployment with custom domain support
3. HTTPS enabled by default

### **Self-Hosted**
- Works with any web server (Apache, Nginx, IIS)
- No server-side processing required
- Just serve static files

## 📊 Command Statistics

| Tool Category | Commands | Protocols/Areas Covered |
|---------------|----------|-------------------------|
| **NetExec** | 50+ | SMB, LDAP, WinRM, MSSQL, SSH |
| **Nmap** | 52+ | Port scanning, service detection, NSE scripts |
| **Web App** | 45+ | SQLi, XSS, directory traversal, API testing |
| **Recon** | 40+ | OSINT, DNS, subdomain enumeration |
| **Exploitation** | 25+ | Metasploit, payload generation, privesc |
| **Password** | 30+ | Hash cracking, brute force, WiFi |
| **Windows** | 35+ | Active Directory, PowerShell, system enum |
| **Linux** | 28+ | System enumeration, file operations |
| **Mobile** | 20+ | Android, iOS security testing |
| **Cloud** | 15+ | AWS, Azure, cloud security |
| **Forensics** | 22+ | Disk analysis, memory forensics |

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### **Adding Commands**
1. Research and verify command syntax
2. Add to appropriate tool database file
3. Include proper descriptions and categories
4. Test with various input combinations

### **Bug Reports**
- Use GitHub Issues
- Include browser version and OS
- Provide steps to reproduce
- Screenshots are helpful

### **Feature Requests**
- Describe the use case
- Explain expected behavior
- Consider implementation complexity

## 📝 License

This project is licensed under the MIT License. See the LICENSE file for details.

## ⚠️ Disclaimer

**Educational and Authorized Testing Only**

This tool is intended for:
- ✅ Educational purposes and learning cybersecurity
- ✅ Authorized penetration testing and security assessments
- ✅ Red team exercises with proper authorization
- ✅ Capture The Flag (CTF) competitions
- ✅ Security research in controlled environments

**NOT intended for:**
- ❌ Unauthorized access to systems
- ❌ Malicious activities or illegal hacking
- ❌ Testing systems without explicit permission

Users are responsible for ensuring they have proper authorization before using any generated commands against systems they do not own.

## 🙏 Acknowledgments

- **NetExec Team**: For the excellent network execution tool
- **Nmap Project**: For the comprehensive network scanner
- **OWASP**: For web application security testing methodologies
- **Penetration Testing Community**: For sharing knowledge and techniques
- **Open Source Contributors**: For tools and techniques referenced

## 📞 Support

- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check the built-in help system (click the Help button)
- **Community**: Join cybersecurity forums and Discord servers

---

**Made with ❤️ for the cybersecurity community**

*Stay ethical, stay curious, and happy hacking!* 🔒