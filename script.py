import subprocess
import socket
import ipaddress
import re
import xml.etree.ElementTree as ET
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
 
# Ensure output directories exist
os.makedirs("output", exist_ok=True)
os.makedirs("output/screenshots", exist_ok=True)
 
def get_local_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)
 
def get_up_hosts(subnet: str, exclude_ip: str):
    print(f"[+] Scanning subnet {subnet} for live hosts (excluding {exclude_ip})...")
    try:
        result = subprocess.run(
            ['nmap', '-sn', subnet],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        raise RuntimeError("Nmap is not installed or not found in PATH.")
 
    up_hosts = []
    for line in result.stdout.splitlines():
        if line.startswith("Nmap scan report for"):
            match = re.search(r"Nmap scan report for ([\d.]+)", line)
            if match:
                ip = match.group(1)
                if ip != exclude_ip:
                    up_hosts.append(ip)
    print(f"[+] {len(up_hosts)} hosts were discovered.")
    return up_hosts
 
def screenshot_web(ip):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "Playwright not installed"
 
    screenshot_path = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
 
            for port in [80, 443]:
                url = f"http://{ip}" if port == 80 else f"https://{ip}"
                try:
                    page.goto(url, timeout=10000)  # 10s timeout
                    screenshot_path = f"output/screenshots/{ip}_{port}.png"
                    page.screenshot(path=screenshot_path)
                    break  # Only one screenshot per host
                except Exception:
                    continue
 
            browser.close()
    except Exception as e:
        return f"Screenshot error: {e}"
 
    return screenshot_path if screenshot_path else "No web interface"
 
def run_nmap_scan(ip: str, flags: list) -> dict:
    try:
        result = subprocess.run(
            ['nmap'] + flags + ['-oX', '-', ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        return {"ip": ip, "error": "Nmap is not installed or not found in PATH."}
 
    host_data = parse_nmap_xml(result.stdout)
    screenshot_path = screenshot_web(ip)
    host_data["screenshot"] = screenshot_path
 
    return host_data
 
def parse_nmap_xml(xml_data: str) -> dict:
    root = ET.fromstring(xml_data)
    host_info = {"os": "Unknown"}
 
    for host in root.findall("host"):
        ip_addr = host.find("address[@addrtype='ipv4']")
        if ip_addr is not None:
            ip = ip_addr.attrib["addr"]
            host_info["ip"] = ip
            try:
                host_info["resolved_name"] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                host_info["resolved_name"] = "Unresolved"
 
        hostname_el = host.find("hostnames/hostname")
        if hostname_el is not None:
            host_info["netbios_name"] = hostname_el.attrib.get("name", "Unknown")
            host_info["hostname"] = hostname_el.attrib.get("name", "Unknown")
 
        os_el = host.find("os/osmatch")
        if os_el is not None:
            host_info["os"] = os_el.attrib.get("name", "Unknown")
        else:
            host_info["os"] = "Unknown"
 
        ports_info = []
        for port in host.findall("ports/port"):
            portid = int(port.attrib["portid"])
            protocol = port.attrib["protocol"]
            state = port.find("state").attrib["state"]
            service_el = port.find("service")
 
            if state == "open":
                port_data = {
                    "port": portid,
                    "protocol": protocol,
                    "service": service_el.attrib.get("name", "unknown"),
                    "version": service_el.attrib.get("version", "unknown")
                }
                ports_info.append(port_data)
 
        host_info.setdefault("ports", []).extend(ports_info)
 
    return host_info
 
def threaded_scan(hosts, flags):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(run_nmap_scan, ip, flags): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"ip": ip, "error": str(e)})
    return results
 
def update_json_file(filename, new_results):
    try:
        with open(filename, "r") as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []
 
    ip_map = {entry["ip"]: entry for entry in existing_data if "ip" in entry}
 
    for result in new_results:
        ip = result.get("ip")
        if ip:
            ip_map[ip] = {**ip_map.get(ip, {}), **result}
 
    with open(filename, "w") as f:
        json.dump(list(ip_map.values()), f, indent=2)
 
def main():
    subnet = input("Enter subnet to scan (e.g., 192.168.0.0/24): ").strip()
    try:
        ip_net = ipaddress.ip_network(subnet)
    except ValueError:
        print("[!] Invalid subnet format.")
        return
 
    local_ip = get_local_ip()
    up_hosts = get_up_hosts(subnet, local_ip)
 
    if not up_hosts:
        print("[!] No hosts found.")
        return
 
    print("[+] Step 1: Fast scan (-F -O)...")
    fast_results = threaded_scan(up_hosts, ['-F', '-O', '-p', '1-100'])
    update_json_file("output/scan_results.json", fast_results)
    print(json.dumps(fast_results, indent=2))
 
    print("[+] Step 2: Top 1000 ports scan...")
    top1000_results = threaded_scan(up_hosts, ['-T4', '-p', '100-1000'])
    update_json_file("output/scan_results.json", top1000_results)
    print(json.dumps(top1000_results, indent=2))
 
    print("[+] Step 3: Full port scan (1000-65535)...")
    full_results = threaded_scan(up_hosts, ['-p', '1000-65535', '-T4'])
    update_json_file("output/scan_results.json", full_results)
    print(json.dumps(full_results, indent=2))
 
    print("[+] Step 4: Version & OS detection on discovered ports...")
    try:
        with open("output/scan_results.json", "r") as f:
            current_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        current_data = []
 
    targeted_scans = []
    for entry in current_data:
        ip = entry.get("ip")
        ports = entry.get("ports", [])
        if ip and ports:
            port_list = ','.join(str(p["port"]) for p in ports)
            targeted_scans.append((ip, port_list))
 
    def run_targeted_scan(ip, ports):
        return run_nmap_scan(ip, ['-sV', '-p', ports, '-T4'])
 
    os_version_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_target = {executor.submit(run_targeted_scan, ip, ports): ip for ip, ports in targeted_scans}
        for future in as_completed(future_to_target):
            ip = future_to_target[future]
            try:
                os_version_results.append(future.result())
            except Exception as e:
                os_version_results.append({"ip": ip, "error": str(e)})
 
    update_json_file("output/scan_results.json", os_version_results)
    print(json.dumps(os_version_results, indent=2))
 
    print("[+] All scans complete. Final results saved to output/scan_results.json")
 
if __name__ == "__main__":
    main()