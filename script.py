import json
import subprocess
import socket
import nmap
import netifaces
import requests
from datetime import datetime
import os

# Required directory setup
os.makedirs("screenshots", exist_ok=True)
os.makedirs("output", exist_ok=True)

# Function to get local subnets
def get_local_subnets():
    subnets = []
    for iface in netifaces.interfaces():
        if netifaces.AF_INET in netifaces.ifaddresses(iface):
            info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip = info['addr']
            netmask = info['netmask']
            if ip != "127.0.0.1":
                cidr = f"{ip}/{sum(bin(int(x)).count('1') for x in netmask.split('.'))}"
                subnets.append(cidr)
    return subnets

# Ping sweep using subprocess
def find_live_hosts(subnet):
    print(f"[*] Scanning subnet: {subnet}")
    result = subprocess.getoutput(f"nmap -sn {subnet}")
    hosts = []
    for line in result.splitlines():
        if "Nmap scan report for" in line:
            ip = line.split()[-1]
            hosts.append(ip)
    return hosts

# Detailed scan per host using nmap
def scan_host(ip):
    scanner = nmap.PortScanner()
    print(f"[*] Scanning host: {ip}")
    scanner.scan(ip, arguments='-sS -sV -O --top-ports 1000')
    info = {
        "ip": ip,
        "hostname": scanner[ip].hostname() if 'hostname' in scanner[ip] else "",
        "os": scanner[ip]['osmatch'][0]['name'] if scanner[ip].has_key('osmatch') and scanner[ip]['osmatch'] else "Unknown",
        "ports": [],
        "tags": []
    }
    for proto in scanner[ip].all_protocols():
        lport = scanner[ip][proto].keys()
        for port in sorted(lport):
            service = scanner[ip][proto][port]['name']
            info["ports"].append({"port": port, "service": service})
            if service in ["http", "https"]:
                info["tags"].append("Web Server")
            if service == "kerberos" or port in [88, 389]:
                info["tags"].append("Domain Controller")
            if service == "microsoft-ds" or port in [445, 139]:
                info["tags"].append("SMB Server")
    return info

# Function to enumerate SMB shares
def enumerate_smb(ip):
    result = subprocess.getoutput(f"smbclient -L \\\\{ip} -N")
    shares = []
    for line in result.splitlines():
        if "Disk" in line:
            shares.append(line.split()[0])
    return shares

# Screenshot web pages
def screenshot_web(ip):
    try:
        import selenium.webdriver
        from selenium.webdriver.chrome.options import Options
        options = Options()
        options.headless = True
        driver = selenium.webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        for port in [80, 443]:
            url = f"http://{ip}" if port == 80 else f"https://{ip}"
            try:
                driver.get(url)
                path = f"screenshots/{ip}_{port}.png"
                driver.save_screenshot(path)
                driver.quit()
                return path
            except Exception:
                continue
        driver.quit()
    except ImportError:
        return "Selenium not installed"

# Main orchestrator
def main():
    final_data = []
    subnets = get_local_subnets()
    for subnet in subnets:
        live_hosts = find_live_hosts(subnet)
        for host in live_hosts:
            host_info = scan_host(host)
            smb_shares = enumerate_smb(host)
            screenshot = screenshot_web(host)
            host_info["smb_shares"] = smb_shares
            host_info["web_screenshot"] = screenshot
            final_data.append(host_info)

    # Save to JSON and POST
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/enumeration_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(final_data, f, indent=4)

    print(f"[*] Results saved to {filename}")

    try:
        print(final_data)
        r = requests.post("http://localhost:8000/api/enumeration", json=final_data)
        print("[*] POST to dashboard response:", r.status_code)
    except ImportError:
        print("[!] Requests not installed, skipping POST.")

    return final_data

results = main()
