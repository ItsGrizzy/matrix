// OSINT & Information Gathering Commands Database

const OSINT_COMMANDS = {
    "Domain & Website Intelligence": [
        { id: 1, name: "Whois Lookup", command: "whois {domain}", description: "Domain registration information", category: "Domain Intelligence" },
        { id: 2, name: "DNS Records", command: "dig {domain} ANY", description: "All DNS records for domain", category: "Domain Intelligence" },
        { id: 3, name: "MX Records", command: "dig {domain} MX", description: "Mail exchange records", category: "Domain Intelligence" },
        { id: 4, name: "TXT Records", command: "dig {domain} TXT", description: "TXT records (SPF, DKIM, etc.)", category: "Domain Intelligence" },
        { id: 5, name: "NS Records", command: "dig {domain} NS", description: "Name server records", category: "Domain Intelligence" },
        { id: 6, name: "Reverse DNS", command: "dig -x {ip}", description: "Reverse DNS lookup", category: "Domain Intelligence" },
        { id: 7, name: "Zone Transfer", command: "dig axfr @{nameserver} {domain}", description: "DNS zone transfer attempt", category: "Domain Intelligence" },
        { id: 8, name: "Certificate Transparency", command: "curl -s 'https://crt.sh/?q={domain}&output=json'", description: "Search certificate transparency logs", category: "Domain Intelligence" },
        { id: 9, name: "Subdomain Brute Force", command: "gobuster dns -d {domain} -w /usr/share/wordlists/dnsmap.txt", description: "Brute force subdomains", category: "Domain Intelligence" },
        { id: 10, name: "DNSRecon", command: "dnsrecon -d {domain} -t axfr,brt,srv,std", description: "Comprehensive DNS enumeration", category: "Domain Intelligence" }
    ],
    
    "Subdomain Enumeration": [
        { id: 11, name: "Subfinder", command: "subfinder -d {domain} -o subdomains.txt", description: "Passive subdomain enumeration", category: "Subdomain Enumeration" },
        { id: 12, name: "Amass", command: "amass enum -d {domain} -o amass_results.txt", description: "In-depth subdomain enumeration", category: "Subdomain Enumeration" },
        { id: 13, name: "Sublist3r", command: "sublist3r -d {domain} -o sublist3r_results.txt", description: "Fast subdomain enumeration", category: "Subdomain Enumeration" },
        { id: 14, name: "Assetfinder", command: "assetfinder {domain}", description: "Find domains and subdomains", category: "Subdomain Enumeration" },
        { id: 15, name: "Findomain", command: "findomain -t {domain}", description: "Cross-platform subdomain enumerator", category: "Subdomain Enumeration" },
        { id: 16, name: "Knockpy", command: "knockpy {domain}", description: "Subdomain scanner with wordlist", category: "Subdomain Enumeration" },
        { id: 17, name: "MassDNS", command: "massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt", description: "High-performance DNS stub resolver", category: "Subdomain Enumeration" },
        { id: 18, name: "DNSx", command: "dnsx -d {domain} -w subdomains.txt", description: "Fast and multi-purpose DNS toolkit", category: "Subdomain Enumeration" },
        { id: 19, name: "Chaos", command: "chaos -d {domain}", description: "Subdomain enumeration using Chaos dataset", category: "Subdomain Enumeration" },
        { id: 20, name: "Github Subdomain Search", command: "github-subdomains -d {domain} -t {github_token}", description: "Find subdomains on GitHub", category: "Subdomain Enumeration" }
    ],
    
    "Email Intelligence": [
        { id: 21, name: "theHarvester", command: "theHarvester -d {domain} -l 500 -b google", description: "Email and subdomain harvesting", category: "Email Intelligence" },
        { id: 22, name: "Hunter.io Search", command: "curl 'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'", description: "Find email addresses using Hunter.io", category: "Email Intelligence" },
        { id: 23, name: "Email Format Discovery", command: "python3 email-enum.py -d {domain}", description: "Discover email format patterns", category: "Email Intelligence" },
        { id: 24, name: "SMTP User Enumeration", command: "smtp-user-enum -M VRFY -U users.txt -t {ip}", description: "SMTP user enumeration", category: "Email Intelligence" },
        { id: 25, name: "Holehe Email Check", command: "holehe {email}", description: "Check if email is used on different sites", category: "Email Intelligence" },
        { id: 26, name: "Sherlock Email", command: "sherlock {username}", description: "Hunt down social media accounts by username", category: "Email Intelligence" },
        { id: 27, name: "Breach Data Check", command: "curl 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}' -H 'hibp-api-key: {api_key}'", description: "Check if email is in data breaches", category: "Email Intelligence" },
        { id: 28, name: "Google Email Dorking", command: "googler '{domain} \"@{domain}\" filetype:pdf'", description: "Google dork for email addresses", category: "Email Intelligence" },
        { id: 29, name: "LinkedIn Email Extraction", command: "linkedin2username -c {company} -f {format}", description: "Extract emails from LinkedIn", category: "Email Intelligence" },
        { id: 30, name: "Infoga", command: "python infoga.py --domain {domain} --source all", description: "Email OSINT tool", category: "Email Intelligence" }
    ],
    
    "Social Media Intelligence": [
        { id: 31, name: "Sherlock Username", command: "sherlock {username}", description: "Find username across social networks", category: "Social Media Intelligence" },
        { id: 32, name: "Social Mapper", command: "python social_mapper.py -f {names_file} -m fast -a linkedin", description: "Social media enumeration", category: "Social Media Intelligence" },
        { id: 33, name: "Twint Twitter OSINT", command: "twint -u {username} --followers", description: "Twitter intelligence gathering", category: "Social Media Intelligence" },
        { id: 34, name: "Instagram OSINT", command: "instaloader --no-posts --no-profile-pic {username}", description: "Instagram profile information", category: "Social Media Intelligence" },
        { id: 35, name: "LinkedIn Enumeration", command: "linkedin2username -c {company}", description: "Enumerate LinkedIn employees", category: "Social Media Intelligence" },
        { id: 36, name: "Facebook Graph Search", command: "fbgraph -t {access_token} /{user_id}", description: "Facebook Graph API search", category: "Social Media Intelligence" },
        { id: 37, name: "GitHub User Enum", command: "gitfive {username}", description: "GitHub user enumeration", category: "Social Media Intelligence" },
        { id: 38, name: "TikTok Profile", command: "tiktok-scraper user {username}", description: "TikTok profile analysis", category: "Social Media Intelligence" },
        { id: 39, name: "Snapchat Username Check", command: "snapchat-username-check {username}", description: "Check Snapchat username availability", category: "Social Media Intelligence" },
        { id: 40, name: "WhatsApp Number Check", command: "whatsapp-check +{phone_number}", description: "Check if phone number uses WhatsApp", category: "Social Media Intelligence" }
    ],
    
    "IP & Network Intelligence": [
        { id: 41, name: "Shodan Search", command: "shodan search 'org:\"{organization}\"'", description: "Search Shodan for organization assets", category: "Network Intelligence" },
        { id: 42, name: "Shodan Host Info", command: "shodan host {ip}", description: "Get detailed host information from Shodan", category: "Network Intelligence" },
        { id: 43, name: "Censys Search", command: "censys search '{query}' --index-type hosts", description: "Search Censys for hosts", category: "Network Intelligence" },
        { id: 44, name: "IP Geolocation", command: "curl 'http://ip-api.com/json/{ip}'", description: "Get IP geolocation information", category: "Network Intelligence" },
        { id: 45, name: "ASN Lookup", command: "whois -h whois.cymru.com ' -v {ip}'", description: "ASN information lookup", category: "Network Intelligence" },
        { id: 46, name: "BGP Information", command: "curl 'https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}'", description: "BGP prefix information", category: "Network Intelligence" },
        { id: 47, name: "IP Range Enumeration", command: "prips {ip_range}", description: "Generate IP range list", category: "Network Intelligence" },
        { id: 48, name: "Network Reconnaissance", command: "masscan -p1-65535 {ip_range} --rate=1000", description: "Fast network port scanning", category: "Network Intelligence" },
        { id: 49, name: "SSL Certificate Info", command: "openssl s_client -connect {ip}:443 -servername {domain}", description: "SSL certificate information", category: "Network Intelligence" },
        { id: 50, name: "Banner Grabbing", command: "nc -nv {ip} {port}", description: "Service banner grabbing", category: "Network Intelligence" }
    ],
    
    "Google Dorking": [
        { id: 51, name: "Site-specific Search", command: "googler 'site:{domain} intext:\"password\"'", description: "Search specific site for passwords", category: "Google Dorking" },
        { id: 52, name: "File Type Search", command: "googler 'site:{domain} filetype:pdf'", description: "Find specific file types", category: "Google Dorking" },
        { id: 53, name: "Login Pages", command: "googler 'site:{domain} inurl:login'", description: "Find login pages", category: "Google Dorking" },
        { id: 54, name: "Admin Panels", command: "googler 'site:{domain} inurl:admin'", description: "Find admin panels", category: "Google Dorking" },
        { id: 55, name: "Directory Listings", command: "googler 'site:{domain} intitle:\"Index of\"'", description: "Find directory listings", category: "Google Dorking" },
        { id: 56, name: "Configuration Files", command: "googler 'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini'", description: "Find configuration files", category: "Google Dorking" },
        { id: 57, name: "Database Files", command: "googler 'site:{domain} ext:sql | ext:dbf | ext:mdb'", description: "Find database files", category: "Google Dorking" },
        { id: 58, name: "Log Files", command: "googler 'site:{domain} ext:log'", description: "Find log files", category: "Google Dorking" },
        { id: 59, name: "Backup Files", command: "googler 'site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup'", description: "Find backup files", category: "Google Dorking" },
        { id: 60, name: "Email Lists", command: "googler 'site:{domain} \"@{domain}\"'", description: "Find email addresses", category: "Google Dorking" }
    ],
    
    "Code Repository Intelligence": [
        { id: 61, name: "GitRob", command: "gitrob -github-access-token {token} {organization}", description: "GitHub organization reconnaissance", category: "Code Repository Intelligence" },
        { id: 62, name: "Gitleaks", command: "gitleaks detect --source . --verbose", description: "Scan for secrets in Git repos", category: "Code Repository Intelligence" },
        { id: 63, name: "TruffleHog", command: "truffleHog --regex --entropy=False https://github.com/{user}/{repo}.git", description: "Search for secrets in Git history", category: "Code Repository Intelligence" },
        { id: 64, name: "GitDorker", command: "python3 GitDorker.py -tf {tokens_file} -q {query} -d {dorks_file}", description: "GitHub dorking tool", category: "Code Repository Intelligence" },
        { id: 65, name: "GitHub Search API", command: "curl -H 'Authorization: token {token}' 'https://api.github.com/search/code?q={query}+user:{user}'", description: "GitHub code search", category: "Code Repository Intelligence" },
        { id: 66, name: "GitLeaks GitHub", command: "gitleaks detect --source https://github.com/{user}/{repo}", description: "Scan GitHub repo for secrets", category: "Code Repository Intelligence" },
        { id: 67, name: "Git-hound", command: "git-hound --subdomain-file subdomains.txt --dig-files --dig-commits", description: "Git repository secret scanner", category: "Code Repository Intelligence" },
        { id: 68, name: "GitHub Recon", command: "github-endpoints.py -t {token} -d {domain}", description: "Find GitHub endpoints for domain", category: "Code Repository Intelligence" },
        { id: 69, name: "Sourcegraph Search", command: "src search '{query} repo:^github.com/{org}/'", description: "Search code using Sourcegraph", category: "Code Repository Intelligence" },
        { id: 70, name: "GitLab Search", command: "curl --header 'PRIVATE-TOKEN: {token}' 'https://gitlab.com/api/v4/search?scope=projects&search={query}'", description: "Search GitLab projects", category: "Code Repository Intelligence" }
    ],
    
    "Company Intelligence": [
        { id: 71, name: "LinkedIn Company Info", command: "linkedin-company-info {company_name}", description: "Get LinkedIn company information", category: "Company Intelligence" },
        { id: 72, name: "Crunchbase Search", command: "curl 'https://api.crunchbase.com/v3.1/organizations/{company}?user_key={api_key}'", description: "Company information from Crunchbase", category: "Company Intelligence" },
        { id: 73, name: "SEC Filings", command: "curl 'https://www.sec.gov/cgi-bin/browse-edgar?company={company}&output=xml'", description: "SEC filing search", category: "Company Intelligence" },
        { id: 74, name: "Google Maps Business", command: "googler '{company_name} site:maps.google.com'", description: "Find business locations", category: "Company Intelligence" },
        { id: 75, name: "Glassdoor Reviews", command: "curl 'https://www.glassdoor.com/Reviews/{company}-Reviews-E{company_id}.htm'", description: "Company reviews and salary info", category: "Company Intelligence" },
        { id: 76, name: "Indeed Company", command: "curl 'https://www.indeed.com/cmp/{company_name}'", description: "Company job listings and info", category: "Company Intelligence" },
        { id: 77, name: "BBB Business Profile", command: "curl 'https://www.bbb.org/search?find_country=USA&find_text={company}'", description: "Better Business Bureau profile", category: "Company Intelligence" },
        { id: 78, name: "Company House UK", command: "curl 'https://api.companieshouse.gov.uk/search/companies?q={company}' -u '{api_key}:'", description: "UK company registration info", category: "Company Intelligence" },
        { id: 79, name: "OpenCorporates", command: "curl 'https://api.opencorporates.com/companies/search?q={company}'", description: "Global company database search", category: "Company Intelligence" },
        { id: 80, name: "Builtwith Technology", command: "curl 'https://api.builtwith.com/v20/api.json?KEY={api_key}&LOOKUP={domain}'", description: "Website technology stack", category: "Company Intelligence" }
    ],
    
    "Phone Number Intelligence": [
        { id: 81, name: "Truecaller Lookup", command: "truecaller-lookup {phone_number}", description: "Phone number owner lookup", category: "Phone Intelligence" },
        { id: 82, name: "Phone Number Validation", command: "curl 'http://apilayer.net/api/validate?access_key={api_key}&number={phone}'", description: "Validate phone number", category: "Phone Intelligence" },
        { id: 83, name: "Carrier Lookup", command: "curl 'https://api.textmagic.com/rest/v2/lookup/{phone_number}' -H 'X-TM-Username: {username}' -H 'X-TM-Key: {api_key}'", description: "Phone carrier information", category: "Phone Intelligence" },
        { id: 84, name: "HLR Lookup", command: "curl 'https://api.hlr-lookups.com/v1/{phone_number}' -H 'Authorization: Bearer {token}'", description: "HLR lookup for phone numbers", category: "Phone Intelligence" },
        { id: 85, name: "Reverse Phone Lookup", command: "phoneinfoga scan -n {phone_number}", description: "Comprehensive phone number scan", category: "Phone Intelligence" },
        { id: 86, name: "Phone Validator", command: "python3 -c \"import phonenumbers; print(phonenumbers.parse('{phone_number}', None))\"", description: "Python phone number validation", category: "Phone Intelligence" },
        { id: 87, name: "SMS Gateway Detection", command: "curl 'https://api.nexmo.com/developer/messages/pricing/outbound/{country_code}' -u '{api_key}:{api_secret}'", description: "SMS gateway information", category: "Phone Intelligence" },
        { id: 88, name: "OSINT Phone Framework", command: "python3 phoneinfoga.py -n {phone_number} --osint", description: "OSINT framework for phone numbers", category: "Phone Intelligence" },
        { id: 89, name: "Phone Country Code", command: "python3 -c \"import phonenumbers; print(phonenumbers.geocoder.description_for_number(phonenumbers.parse('{phone_number}', None), 'en'))\"", description: "Get country from phone number", category: "Phone Intelligence" },
        { id: 90, name: "WhatsApp Number Check", command: "python3 whatsapp_check.py {phone_number}", description: "Check if number is on WhatsApp", category: "Phone Intelligence" }
    ],
    
    "Dark Web Intelligence": [
        { id: 91, name: "OnionScan", command: "onionscan {onion_address}", description: "Scan Tor hidden services", category: "Dark Web Intelligence" },
        { id: 92, name: "Ahmia Search", command: "curl 'https://ahmia.fi/search/?q={query}'", description: "Search Tor hidden services", category: "Dark Web Intelligence" },
        { id: 93, name: "DarkSearch", command: "curl 'https://darksearch.io/api/search?query={query}'", description: "Dark web search engine", category: "Dark Web Intelligence" },
        { id: 94, name: "Torch Search", command: "torify curl 'http://torch.onion/search?q={query}'", description: "Search via Torch search engine", category: "Dark Web Intelligence" },
        { id: 95, name: "Hidden Service Discovery", command: "python3 onionscan.py --scan {onion_domain}", description: "Comprehensive onion service scan", category: "Dark Web Intelligence" },
        { id: 96, name: "Tor Directory", command: "torify curl 'http://directory.onion/search?q={query}'", description: "Search Tor directory listings", category: "Dark Web Intelligence" },
        { id: 97, name: "Paste Site Monitoring", command: "python3 paste_monitor.py --query '{company_name}'", description: "Monitor paste sites for data", category: "Dark Web Intelligence" },
        { id: 98, name: "Breach Database Search", command: "python3 breach_search.py --domain {domain}", description: "Search known data breaches", category: "Dark Web Intelligence" },
        { id: 99, name: "Darknet Market Monitor", command: "python3 darknet_monitor.py --keywords '{keywords}'", description: "Monitor darknet markets", category: "Dark Web Intelligence" },
        { id: 100, name: "Cryptocurrency Tracking", command: "python3 crypto_track.py --address {btc_address}", description: "Track cryptocurrency transactions", category: "Dark Web Intelligence" }
    ]
};