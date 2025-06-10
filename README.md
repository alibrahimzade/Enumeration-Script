#  Network Enumeration & Web Interface Screenshot Tool

This Python tool performs multi-phase network scanning using **Nmap**, detects live hosts, scans for open ports and services, identifies operating systems, and takes **web interface screenshots** (via HTTP/HTTPS) using Playwright.

## Features

- Subnet discovery and host detection
- Fast scan (-F), top 1000 ports, full port scan
- OS & version detection
- Screenshot capture of web interfaces (port 80/443)
- Threaded scanning for performance
- Saves results in structured JSON (`output/scan_results.json`)
- Screenshot images saved under `output/screenshots/`

---

## Requirements

- Python 3.7+
- [Nmap](https://nmap.org/) installed and added to system `PATH`
- Google Chrome (Playwright uses it for headless screenshot)
- Internet access (if scanning across networks)

---

## 📥 Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/your-username/network-enumeration.git



pip install -r requirements.txt

python .\script.py
