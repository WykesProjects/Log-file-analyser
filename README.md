# Log File Analyser

This project is a **Python-based analyser** for Windows Defender Firewall logs.  
It parses firewall log files (`pfirewall.log`) and produces a security summary.  

## Features
- Counts **ALLOW** and **DROP** actions
- Identifies the **top 5 most common source IPs**
- Highlights the **top 5 destination ports**
- Lists IPs sending and receiving traffic
- Flags connections on **suspicious ports** (e.g. SMB 445, RDP 3389, SSH 22, Telnet 23)

## Example Log
The repo includes a sample `pfirewall.log` with 20 lines of mixed ALLOW/DROP traffic.  

## 🖥️ Usage
1. Clone this repo:
   ```bash
   git clone https://github.com/WykesProjects/Log-file-analyser.git
   cd Log-file-analyser