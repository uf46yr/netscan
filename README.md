### NetScan Professional Overview
**NetScan Professional v2.1** is a powerful network reconnaissance tool for Linux and Termux (Android). It automates comprehensive scans including WHOIS lookups, DNS analysis, IP geolocation, and Nmap-based port/service detection. Key features:

1. **Host Check**: Verifies target reachability via ICMP ping.
2. **WHOIS Lookup**: Retrieves domain/IP registration details.
3. **DNS Analysis**: Checks A, AAAA, MX, NS, and PTR records.
4. **IP Geolocation**: Identifies country, city, ASN, and ISP.
5. **Nmap Scanning**:  
   - **Comprehensive Scan**: All 65,535 ports + service/OS detection (requires root).  
   - **Fast Scan**: Top 1,000 ports (use `-f` flag).  
   - Outputs color-coded results (critical services like SSH/FTP highlighted in red).

---

### Installation & Usage  
#### **Termux (Android)**  
1. **Install Dependencies**:  
   ```bash
   pkg update && pkg upgrade
   pkg install nmap whois dnsutils curl jq
   ```
2. **Make Script Executable**:  
   ```bash
   chmod +x netscan.sh
   ```
3. **Run Scans**:  
   - Comprehensive scan:  
     ```bash
     ./netscan.sh example.com
     ```
   - Fast scan (top ports):  
     ```bash
     ./netscan.sh -f 192.168.1.1
     ```
   - Save results to file:  
     ```bash
     ./netscan.sh -o report.txt example.com
     ```

#### **Linux (Debian/Ubuntu)**  
1. **Install Dependencies**:  
   ```bash
   sudo apt update && sudo apt upgrade
   sudo apt install nmap whois dnsutils curl jq
   ```
2. **Make Script Executable**:  
   ```bash
   chmod +x netscan.sh
   ```
3. **Run Scans**:  
   - Basic scan:  
     ```bash
     ./netscan.sh example.com
     ```
   - Full OS detection (requires root):  
     ```bash
     sudo ./netscan.sh example.com
     ```
   - Fast scan + save output:  
     ```bash
     ./netscan.sh -f -o report.txt 192.168.1.1
     ```

---

### Key Notes  
- **Critical Services**: SSH, FTP, HTTP/S, RDP, etc., are highlighted in red for quick identification.  
- **Output**: Use `-o filename.txt` to save full results.  
- **Performance**:  
  - Fast Scan: 1-5 minutes.  
  - Comprehensive Scan: 10-30 minutes.  
- **Root Privileges**: Required for OS detection and SYN scans on Linux. Termux doesn't require root.  

> **Example Output Snippet**:  
> ```
> PORT    STATE  SERVICE       VERSION  
> 22/tcp  open   ssh           OpenSSH 8.2p1  
> 80/tcp  open   http          Apache httpd 2.4.41  
> 443/tcp open   ssl/http      Apache httpd 2.4.41  
> ```  
> Critical services appear in red.

---

### Troubleshooting  
- **Missing Tools**: The script checks dependencies and provides installation commands.  
- **Host Unreachable**: Scans proceed even if ICMP is blocked.  
- **API Errors**: IP geolocation uses `ipinfo.io` (ensure internet access).  

NetScan Professional streamlines network diagnostics with minimal setup—ideal for penetration testers and sysadmins.
