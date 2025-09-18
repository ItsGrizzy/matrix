// Wireless Security Testing Commands Database

const WIRELESS_COMMANDS = {
    "WiFi Reconnaissance": [
        { id: 1, name: "Monitor Mode Enable", command: "airmon-ng start {interface}", description: "Enable monitor mode on wireless interface", category: "WiFi Reconnaissance" },
        { id: 2, name: "WiFi Networks Scan", command: "airodump-ng {monitor_interface}", description: "Scan for WiFi networks", category: "WiFi Reconnaissance" },
        { id: 3, name: "Target Network Monitor", command: "airodump-ng -c {channel} --bssid {bssid} -w {output_file} {monitor_interface}", description: "Monitor specific WiFi network", category: "WiFi Reconnaissance" },
        { id: 4, name: "WiFi Interface Info", command: "iwconfig", description: "Display wireless interface information", category: "WiFi Reconnaissance" },
        { id: 5, name: "Wireless Extensions", command: "iwlist {interface} scan", description: "List available wireless networks", category: "WiFi Reconnaissance" },
        { id: 6, name: "WiFi Signal Strength", command: "iwlist {interface} scanning | grep -E 'ESSID|Quality'", description: "Show WiFi signal strength", category: "WiFi Reconnaissance" },
        { id: 7, name: "Channel Utilization", command: "wavemon -i {interface}", description: "Monitor wireless channel utilization", category: "WiFi Reconnaissance" },
        { id: 8, name: "WiFi Frequency Info", command: "iwlist {interface} frequency", description: "Show available frequencies", category: "WiFi Reconnaissance" },
        { id: 9, name: "Wireless Statistics", command: "cat /proc/net/wireless", description: "Display wireless statistics", category: "WiFi Reconnaissance" },
        { id: 10, name: "Hidden Network Scan", command: "airodump-ng --manufacturer --wps --gpsd {monitor_interface}", description: "Enhanced WiFi scanning with GPS", category: "WiFi Reconnaissance" }
    ],
    
    "WPA/WPA2 Attacks": [
        { id: 11, name: "WPA Handshake Capture", command: "airodump-ng -c {channel} --bssid {bssid} -w {capture_file} {monitor_interface}", description: "Capture WPA handshake", category: "WPA/WPA2 Attacks" },
        { id: 12, name: "Deauth Attack", command: "aireplay-ng --deauth {num_packets} -a {bssid} -c {client_mac} {monitor_interface}", description: "Deauthenticate client to capture handshake", category: "WPA/WPA2 Attacks" },
        { id: 13, name: "WPA Dictionary Attack", command: "aircrack-ng -w {wordlist} -b {bssid} {capture_file}.cap", description: "Crack WPA/WPA2 with dictionary", category: "WPA/WPA2 Attacks" },
        { id: 14, name: "Hashcat WPA Crack", command: "hashcat -m 2500 -a 0 {capture_file}.hccapx {wordlist}", description: "GPU-accelerated WPA cracking", category: "WPA/WPA2 Attacks" },
        { id: 15, name: "John WPA Crack", command: "john --wordlist={wordlist} {capture_file}.john", description: "John the Ripper WPA cracking", category: "WPA/WPA2 Attacks" },
        { id: 16, name: "WPA2 PMKID Attack", command: "hcxdumptool -i {interface} -o {output_file}.pcapng --enable_status=1", description: "Capture PMKID for WPA2 cracking", category: "WPA/WPA2 Attacks" },
        { id: 17, name: "PMKID to Hashcat", command: "hcxpcaptool -z {pmkid_file}.16800 {capture_file}.pcapng", description: "Convert PMKID for Hashcat", category: "WPA/WPA2 Attacks" },
        { id: 18, name: "WPA3 SAE Attack", command: "wpa_supplicant -i {interface} -c wpa_supplicant.conf -D nl80211", description: "WPA3 SAE handshake attack", category: "WPA/WPA2 Attacks" },
        { id: 19, name: "WPS PIN Attack", command: "reaver -i {monitor_interface} -b {bssid} -vv", description: "WPS PIN brute force attack", category: "WPA/WPA2 Attacks" },
        { id: 20, name: "Pixie Dust Attack", command: "reaver -i {monitor_interface} -b {bssid} -K", description: "WPS Pixie Dust attack", category: "WPA/WPA2 Attacks" }
    ],
    
    "WEP Attacks": [
        { id: 21, name: "WEP Data Capture", command: "airodump-ng -c {channel} --bssid {bssid} -w {capture_file} {monitor_interface}", description: "Capture WEP encrypted data", category: "WEP Attacks" },
        { id: 22, name: "ARP Request Replay", command: "aireplay-ng --arpreplay -b {bssid} -h {client_mac} {monitor_interface}", description: "ARP replay attack to generate traffic", category: "WEP Attacks" },
        { id: 23, name: "Fake Authentication", command: "aireplay-ng --fakeauth 0 -a {bssid} -h {client_mac} {monitor_interface}", description: "Fake authentication with AP", category: "WEP Attacks" },
        { id: 24, name: "WEP Key Crack", command: "aircrack-ng {capture_file}.cap", description: "Crack WEP key from capture file", category: "WEP Attacks" },
        { id: 25, name: "ChopChop Attack", command: "aireplay-ng --chopchop -b {bssid} -h {client_mac} {monitor_interface}", description: "ChopChop attack against WEP", category: "WEP Attacks" },
        { id: 26, name: "Fragment Attack", command: "aireplay-ng --fragment -b {bssid} -h {client_mac} {monitor_interface}", description: "Fragment attack to obtain keystream", category: "WEP Attacks" },
        { id: 27, name: "Interactive Packet Replay", command: "aireplay-ng --interactive -b {bssid} -h {client_mac} -r {replay_file} {monitor_interface}", description: "Interactive packet replay", category: "WEP Attacks" },
        { id: 28, name: "Caffe Latte Attack", command: "aireplay-ng --caffe-latte -b {bssid} {monitor_interface}", description: "Client-side WEP attack", category: "WEP Attacks" },
        { id: 29, name: "Hirte Attack", command: "aireplay-ng --cfrag -b {bssid} {monitor_interface}", description: "Fragmentation attack variant", category: "WEP Attacks" },
        { id: 30, name: "WEP Statistical Attack", command: "aircrack-ng -K {capture_file}.cap", description: "WEP statistical attack (Korek)", category: "WEP Attacks" }
    ],
    
    "Evil Twin Attacks": [
        { id: 31, name: "Hostapd Setup", command: "hostapd /etc/hostapd/hostapd.conf", description: "Start hostapd access point", category: "Evil Twin Attacks" },
        { id: 32, name: "DHCP Server", command: "dnsmasq -C /etc/dnsmasq.conf", description: "Start DHCP server for evil twin", category: "Evil Twin Attacks" },
        { id: 33, name: "Airbase-ng AP", command: "airbase-ng -e '{ssid}' -c {channel} {monitor_interface}", description: "Create fake access point", category: "Evil Twin Attacks" },
        { id: 34, name: "Karma Attack", command: "airbase-ng -P -C 30 -e '{ssid}' {monitor_interface}", description: "Karma attack - respond to all probes", category: "Evil Twin Attacks" },
        { id: 35, name: "WiFi Pineapple", command: "pineapple_connector --start", description: "Start WiFi Pineapple attack", category: "Evil Twin Attacks" },
        { id: 36, name: "Fluxion Attack", command: "fluxion", description: "Automated evil twin attack", category: "Evil Twin Attacks" },
        { id: 37, name: "WiFiPhisher", command: "wifiphisher -i {interface} -e {target_ssid}", description: "Automated phishing attack", category: "Evil Twin Attacks" },
        { id: 38, name: "Portal Captive", command: "python3 portal_captive.py --interface {interface} --ssid '{ssid}'", description: "Captive portal attack", category: "Evil Twin Attacks" },
        { id: 39, name: "EAPHammer", command: "eaphammer -i {interface} --channel {channel} --auth wpa-eap --essid '{ssid}'", description: "EAP credential harvesting", category: "Evil Twin Attacks" },
        { id: 40, name: "Bettercap Evil Twin", command: "bettercap -iface {interface} -caplet evil-twin.cap", description: "Bettercap evil twin module", category: "Evil Twin Attacks" }
    ],
    
    "Bluetooth Attacks": [
        { id: 41, name: "Bluetooth Scan", command: "hcitool scan", description: "Scan for Bluetooth devices", category: "Bluetooth Attacks" },
        { id: 42, name: "Bluetooth Info", command: "hciconfig -a", description: "Display Bluetooth adapter info", category: "Bluetooth Attacks" },
        { id: 43, name: "Device Discovery", command: "bluetoothctl scan on", description: "Continuous Bluetooth scanning", category: "Bluetooth Attacks" },
        { id: 44, name: "Service Discovery", command: "sdptool browse {bluetooth_mac}", description: "Browse Bluetooth services", category: "Bluetooth Attacks" },
        { id: 45, name: "Bluetooth Sniffing", command: "hcidump -w {output_file}.dump", description: "Capture Bluetooth traffic", category: "Bluetooth Attacks" },
        { id: 46, name: "BlueSnarfing", command: "bluesnarfer -b {bluetooth_mac} -C 7", description: "Extract data from Bluetooth device", category: "Bluetooth Attacks" },
        { id: 47, name: "BlueBugging", command: "btscanner -i {interface}", description: "Bluetooth device vulnerability scanner", category: "Bluetooth Attacks" },
        { id: 48, name: "BlueZ Scanner", command: "l2ping {bluetooth_mac}", description: "Bluetooth L2CAP ping", category: "Bluetooth Attacks" },
        { id: 49, name: "OBEX Push", command: "obexftp -b {bluetooth_mac} -p {file}", description: "Push file via OBEX", category: "Bluetooth Attacks" },
        { id: 50, name: "Bluetooth Fuzzing", command: "bss -b {bluetooth_mac} -f", description: "Bluetooth stack smasher", category: "Bluetooth Attacks" }
    ],
    
    "RFID/NFC Attacks": [
        { id: 51, name: "NFC Scan", command: "nfc-scan-device", description: "Scan for NFC devices", category: "RFID/NFC Attacks" },
        { id: 52, name: "RFID Read", command: "proxmark3 /dev/ttyACM0 -c 'lf search'", description: "Search for LF RFID tags", category: "RFID/NFC Attacks" },
        { id: 53, name: "NFC List", command: "nfc-list", description: "List NFC devices and targets", category: "RFID/NFC Attacks" },
        { id: 54, name: "Mifare Classic Read", command: "mfoc -O {output_file}.dump", description: "Crack Mifare Classic keys", category: "RFID/NFC Attacks" },
        { id: 55, name: "HF RFID Scan", command: "proxmark3 /dev/ttyACM0 -c 'hf search'", description: "Search for HF RFID tags", category: "RFID/NFC Attacks" },
        { id: 56, name: "RFID Clone", command: "proxmark3 /dev/ttyACM0 -c 'lf em 410x clone {card_id}'", description: "Clone EM410x RFID card", category: "RFID/NFC Attacks" },
        { id: 57, name: "NFC Relay Attack", command: "nfc-relay-picc", description: "NFC relay attack tool", category: "RFID/NFC Attacks" },
        { id: 58, name: "Chameleon Mini", command: "chameleon-mini.exe -p COM3 -c 'config=MF_CLASSIC_1K'", description: "Configure Chameleon Mini", category: "RFID/NFC Attacks" },
        { id: 59, name: "ACR122U Reader", command: "nfc-mfclassic r a {dump_file}.dump {device}", description: "Read Mifare Classic with ACR122U", category: "RFID/NFC Attacks" },
        { id: 60, name: "Flipper Zero", command: "qFlipper --cli --upload {file_path}", description: "Upload file to Flipper Zero", category: "RFID/NFC Attacks" }
    ],
    
    "Software Defined Radio": [
        { id: 61, name: "RTL-SDR Scanner", command: "rtl_fm -f {frequency}M -M wbfm -s 200000 -r 48000 - | aplay -r 48k -f S16_LE", description: "RTL-SDR FM radio scanner", category: "Software Defined Radio" },
        { id: 62, name: "GQRX Spectrum", command: "gqrx", description: "Software defined radio receiver", category: "Software Defined Radio" },
        { id: 63, name: "RTL433 Decoder", command: "rtl_433 -f {frequency}M", description: "Decode 433MHz devices", category: "Software Defined Radio" },
        { id: 64, name: "HackRF One", command: "hackrf_info", description: "Display HackRF device information", category: "Software Defined Radio" },
        { id: 65, name: "GNU Radio Companion", command: "gnuradio-companion", description: "Visual SDR programming environment", category: "Software Defined Radio" },
        { id: 66, name: "Frequency Scanner", command: "rtl_power -f {start_freq}M:{end_freq}M:{step} -i {interval} {output_file}.csv", description: "RF frequency power scanner", category: "Software Defined Radio" },
        { id: 67, name: "POCSAG Decoder", command: "multimon-ng -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -t raw /dev/stdin", description: "Decode POCSAG pager signals", category: "Software Defined Radio" },
        { id: 68, name: "ADS-B Decoder", command: "dump1090 --interactive --net", description: "Decode aircraft ADS-B signals", category: "Software Defined Radio" },
        { id: 69, name: "GSM Scanner", command: "grgsm_scanner -b", description: "GSM cellular scanner", category: "Software Defined Radio" },
        { id: 70, name: "TPMS Decoder", command: "rtl_433 -R 60", description: "Tire pressure monitoring decoder", category: "Software Defined Radio" }
    ],
    
    "Wireless Tools": [
        { id: 71, name: "WiFite Automated", command: "wifite --kill", description: "Automated WiFi auditing", category: "Wireless Tools" },
        { id: 72, name: "Bettercap", command: "bettercap -iface {interface}", description: "Network attack and monitoring framework", category: "Wireless Tools" },
        { id: 73, name: "Kismet Server", command: "kismet_server", description: "Wireless network detector", category: "Wireless Tools" },
        { id: 74, name: "LinSSID", command: "linssid", description: "Graphical WiFi scanner for Linux", category: "Wireless Tools" },
        { id: 75, name: "WiFi Analyzer", command: "wavemon", description: "Console WiFi network monitor", category: "Wireless Tools" },
        { id: 76, name: "Fern WiFi Cracker", command: "fern-wifi-cracker", description: "Wireless security auditing tool", category: "Wireless Tools" },
        { id: 77, name: "Cowpatty", command: "cowpatty -f {wordlist} -r {capture_file}.cap -s {ssid}", description: "WPA-PSK dictionary attack", category: "Wireless Tools" },
        { id: 78, name: "Pyrit", command: "pyrit -r {capture_file}.cap -i {wordlist} attack_db", description: "GPU-accelerated WPA cracking", category: "Wireless Tools" },
        { id: 79, name: "Airgraph-ng", command: "airgraph-ng -i {dump_file}.csv -g CAPR -o {output_graph}.png", description: "Create graphs from airodump data", category: "Wireless Tools" },
        { id: 80, name: "Wifijammer", command: "python wifijammer.py", description: "Continuously jam WiFi networks", category: "Wireless Tools" }
    ],
    
    "Mobile Network Testing": [
        { id: 81, name: "GSM Sniffing", command: "grgsm_livemon -f {frequency}", description: "Live GSM monitoring", category: "Mobile Network Testing" },
        { id: 82, name: "IMSI Catcher", command: "gr-gsm_scanner", description: "Detect IMSI catchers", category: "Mobile Network Testing" },
        { id: 83, name: "LTE Scanner", command: "python lte_scan.py --freq {frequency}", description: "LTE network scanner", category: "Mobile Network Testing" },
        { id: 84, name: "Femtocell Detection", command: "python detect_femtocell.py --interface {interface}", description: "Detect rogue femtocells", category: "Mobile Network Testing" },
        { id: 85, name: "SMS Intercept", command: "grgsm_decode -c {channel} -f {frequency}", description: "Intercept GSM SMS messages", category: "Mobile Network Testing" },
        { id: 86, name: "USRP B200", command: "uhd_usrp_probe", description: "USRP software defined radio probe", category: "Mobile Network Testing" },
        { id: 87, name: "OpenBTS", command: "OpenBTS", description: "Open source GSM base station", category: "Mobile Network Testing" },
        { id: 88, name: "BladeRF", command: "bladeRF-cli -p", description: "BladeRF command line interface", category: "Mobile Network Testing" },
        { id: 89, name: "YateBTS", command: "yate", description: "Software GSM base transceiver station", category: "Mobile Network Testing" },
        { id: 90, name: "Kalibrate", command: "kal -s GSM900", description: "GSM base station scanner", category: "Mobile Network Testing" }
    ]
};