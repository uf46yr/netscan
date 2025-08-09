#!/bin/bash

# NetScan Professional
# Version 1.3

# Colors for the output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# OS detection
OS="unknown"
if [ -f /etc/os-release ]; then
    OS="linux"
elif [ -d /data/data/com.termux/files/usr ]; then
    OS="termux"
fi

# Display help information
show_help() {
    echo -e "${GREEN}NetScan Professional - Network Scanning Tool v1.3${NC}"
    echo -e "Usage: ${YELLOW}$0 [options] ${RED}[target]${NC}"
    echo
    echo "Options:"
    echo -e "  ${CYAN}-h, --help${NC}     Show this help message"
    echo -e "  ${CYAN}-v, --version${NC}  Show version information"
    echo -e "  ${CYAN}-f, --fast${NC}     Fast scan (top 1000 ports)"
    echo -e "  ${CYAN}-o, --output${NC}   Save full results to file"
    echo
    echo "Target:"
    echo -e "  ${RED}IP address${NC} or ${RED}domain name${NC} to scan"
    echo
    echo "Scan Features:"
    echo "  - WHOIS lookup"
    echo "  - DNS analysis"
    echo "  - IP geolocation"
    echo "  - Full port scanning with Nmap"
    echo "  - Service and version detection"
    echo "  - OS detection (with root privileges)"
    echo "  - Host availability check"
    echo "  - Vulnerability scanning (vulners.nse)"
    echo "  - Cloudflare bypass techniques"
    echo "  - DDoS Guard bypass techniques"
    echo
    echo -e "${BLUE}Installation Instructions:${NC}"

    if [ "$OS" = "termux" ]; then
        echo -e "${GREEN}For Termux:${NC}"
        echo "  1. Update packages:"
        echo -e "     ${YELLOW}pkg update && pkg upgrade${NC}"
        echo "  2. Install dependencies:"
        echo -e "     ${YELLOW}pkg install nmap whois dnsutils curl jq${NC}"
        echo "  3. Make script executable:"
        echo -e "     ${YELLOW}chmod +x netscan.sh${NC}"
        echo "  4. Run script:"
        echo -e "     ${YELLOW}./netscan.sh ${RED}example.com${NC}"
        echo -e "     ${YELLOW}./netscan.sh -f ${RED}192.168.1.1${NC} ${GREEN}# Fast scan${NC}"
        echo -e "     ${YELLOW}./netscan.sh -o scan_report.txt ${RED}example.com${NC} ${GREEN}# Save results${NC}"
    else
        echo -e "${GREEN}For Linux (Debian/Ubuntu):${NC}"
        echo "  1. Update packages:"
        echo -e "     ${YELLOW}sudo apt update && sudo apt upgrade${NC}"
        echo "  2. Install dependencies:"
        echo -e "     ${YELLOW}sudo apt install nmap whois dnsutils curl jq${NC}"
        echo "  3. Make script executable:"
        echo -e "     ${YELLOW}chmod +x netscan.sh${NC}"
        echo "  4. Run script:"
        echo -e "     ${YELLOW}./netscan.sh ${RED}example.com${NC}"
        echo -e "     ${YELLOW}sudo ./netscan.sh ${RED}example.com${NC} ${GREEN}# For OS detection${NC}"
        echo -e "     ${YELLOW}./netscan.sh -f ${RED}192.168.1.1${NC} ${GREEN}# Fast scan${NC}"
        echo -e "     ${YELLOW}./netscan.sh -o scan_report.txt ${RED}example.com${NC} ${GREEN}# Save results${NC}"
    fi

    echo
    echo -e "${BLUE}Scanning Modes:${NC}"
    echo -e "  ${CYAN}Comprehensive Scan${NC}:"
    echo "    - Scans all 65535 ports"
    echo "    - Service version detection"
    echo "    - OS detection (with root)"
    echo "    - Full vulnerability assessment"
    echo -e "    ${YELLOW}./netscan.sh ${RED}target${NC}"

    echo -e "  ${CYAN}Fast Scan${NC}:"
    echo "    - Scans top 1000 ports"
    echo "    - Quick service identification"
    echo "    - MAX scanning speed (T5)"
    echo "    - Vulnerability scanning"
    echo -e "    ${YELLOW}./netscan.sh -f ${RED}target${NC}"

    echo
    echo -e "${GREEN}Note:${NC} For full functionality (OS detection, SYN scan), run the script with root privileges."
    exit 0
}

# Show version information
show_version() {
    echo -e "${GREEN}NetScan Professional v1.3${NC}"
    echo "Author: Network Security Expert"
    echo "License: MIT"
    exit 0
}

# Error handling function
error() {
    echo -e "${RED}[!] Error: $1${NC}" >&2
}

# Checking dependencies
check_dependencies() {
    local missing=()
    local tools=("nmap" "ping" "whois" "dig" "curl" "jq" "nslookup")

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        error "Required tools are missing:"
        for item in "${missing[@]}"; do
            case $item in
                "nmap")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • nmap: ${RED}install with: pkg install nmap${NC}"
                    else
                        echo -e "  • nmap: ${RED}install with: sudo apt install nmap${NC}"
                    fi
                    ;;
                "whois")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • whois: ${RED}install with: pkg install whois${NC}"
                    else
                        echo -e "  • whois: ${RED}install with: sudo apt install whois${NC}"
                    fi
                    ;;
                "dig")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • dig: ${RED}install with: pkg install dnsutils${NC}"
                    else
                        echo -e "  • dig: ${RED}install with: sudo apt install dnsutils${NC}"
                    fi
                    ;;
                "curl")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • curl: ${RED}install with: pkg install curl${NC}"
                    else
                        echo -e "  • curl: ${RED}install with: sudo apt install curl${NC}"
                    fi
                    ;;
                "jq")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • jq: ${RED}install with: pkg install jq${NC}"
                    else
                        echo -e "  • jq: ${RED}install with: sudo apt install jq${NC}"
                    fi
                    ;;
                "nslookup")
                    if [ "$OS" = "termux" ]; then
                        echo -e "  • nslookup: ${RED}install with: pkg install dnsutils${NC}"
                    else
                        echo -e "  • nslookup: ${RED}install with: sudo apt install dnsutils${NC}"
                    fi
                    ;;
                *)
                    echo -e "  • $item: ${RED}not installed${NC}"
                    ;;
            esac
        done
        exit 1
    fi
}

# Improved host availability check
check_host() {
    echo -e "${CYAN}[*] Checking availability: ${YELLOW}$1${NC}"

    # Use different ping parameters based on OS
    if [ "$OS" = "termux" ]; then
        if ping -c 2 -w 2 "$1" &> /dev/null; then
            echo -e "${GREEN}  [+] Host is reachable (ping)${NC}"
            return 0
        else
            echo -e "${RED}  [!] Host is not responding to ping${NC}"
            return 1
        fi
    else
        if ping -c 2 -W 1 "$1" &> /dev/null; then
            echo -e "${GREEN}  [+] Host is reachable (ping)${NC}"
            return 0
        else
            echo -e "${RED}  [!] Host is not responding to ping${NC}"
            return 1
        fi
    fi
}

# WHOIS information lookup
get_whois() {
    echo -e "${CYAN}[*] WHOIS lookup: ${YELLOW}$1${NC}"
    local whois_result

    if [ "$OS" = "termux" ]; then
        whois_result=$(whois "$1" 2>&1)
    else
        whois_result=$(whois -H "$1" 2>&1)
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}  [!] Error executing whois${NC}"
        return
    fi

    local filtered_result=$(echo "$whois_result" | grep -Ei "inetnum|netname|descr|organization|org-name|orgname|country|created|changed|aut-num|origin" | head -20)

    if [ -z "$filtered_result" ]; then
        echo -e "${RED}  [!] WHOIS information not found${NC}"
    else
        echo "$filtered_result"
    fi
    echo
}

# Helper function to check if IP is in CIDR range
ip_in_range() {
    local ip="$1"
    local cidr="$2"

    if ! command -v ipcalc &> /dev/null; then
        # Fallback to simple check if ipcalc not available
        [[ "$ip" == "${cidr%/*}"* ]] && return 0 || return 1
    fi

    local ip_dec
    ip_dec=$(echo "$ip" | tr '.' ' ' | awk '{print ($1*(256^3)) + ($2*(256^2)) + ($3*256) + $4}')
    local network="${cidr%/*}"
    local mask="${cidr#*/}"

    local net_dec
    net_dec=$(echo "$network" | tr '.' ' ' | awk '{print ($1*(256^3)) + ($2*(256^2)) + ($3*256) + $4}')

    local mask_dec=$((0xffffffff << (32 - mask) & 0xffffffff))

    if (( (ip_dec & mask_dec) == (net_dec & mask_dec) )); then
        return 0
    else
        return 1
    fi
}

# Cloudflare bypass detection and techniques
bypass_cloudflare() {
    local domain="$1"
    echo -e "${CYAN}[*] Cloudflare Bypass Techniques: ${YELLOW}$domain${NC}"

    # Check if Cloudflare is detected
    local ns_result
    ns_result=$(dig +short ns "$domain" 2>/dev/null)
    local is_cloudflare=0

    if echo "$ns_result" | grep -qi "cloudflare"; then
        is_cloudflare=1
        echo -e "${RED}  [Cloudflare] Domain protected by Cloudflare DNS${NC}"
    fi

    # Check Cloudflare IP ranges (common IPv4 ranges)
    local ip_checks=0
    local a_record
    a_record=$(dig +short a "$domain" 2>/dev/null | head -1)

    if [[ -n "$a_record" ]]; then
        # Check if IP belongs to Cloudflare
        if [[ $a_record =~ ^(173\.245\.4[8-9]|173\.245\.5[0-9]|173\.245\.6[0-3]|103\.21\.24[4-7]|103\.22\.20[0-3]) ]]; then
            is_cloudflare=1
            ip_checks=1
            echo -e "${RED}  [Cloudflare] IP $a_record belongs to Cloudflare network${NC}"
        fi
    fi

    if [[ $is_cloudflare -eq 0 ]]; then
        echo -e "${GREEN}  [Status] No Cloudflare protection detected${NC}"
        return
    fi

    echo -e "${PURPLE}  [Bypass Methods] Trying to discover real IP:${NC}"

    # 1. Check common subdomains
    echo -e "${BLUE}  [DNS] Checking common subdomains:${NC}"
    local subdomains=("direct" "origin" "ns1" "ns2" "mail" "ftp" "cpanel" "whm" "server" "old" "test")
    local found_subdomain=0

    for sub in "${subdomains[@]}"; do
        local full_sub="${sub}.${domain}"
        local sub_ip
        sub_ip=$(dig +short a "$full_sub" 2>/dev/null | head -1)

        if [[ -n "$sub_ip" ]]; then
            # Skip Cloudflare IPs if we're detecting them
            if [[ $ip_checks -eq 1 ]] && [[ $sub_ip == "$a_record" ]]; then
                continue
            fi

            echo -e "    ${GREEN}$full_sub -> $sub_ip${NC}"
            found_subdomain=1
        fi
    done

    if [[ $found_subdomain -eq 0 ]]; then
        echo -e "    ${RED}No revealing subdomains found${NC}"
    fi

    # 2. Check MX records
    echo -e "${BLUE}  [MX] Mail server records:${NC}"
    local mx_records
    mx_records=$(dig +short mx "$domain" 2>/dev/null)
    local found_mx=0

    if [[ -n "$mx_records" ]]; then
        while read -r priority record; do
            local mx_ip
            mx_ip=$(dig +short a "$record" 2>/dev/null | head -1)
            if [[ -n "$mx_ip" ]]; then
                echo -e "    ${GREEN}$record -> $mx_ip (Priority: $priority)${NC}"
                found_mx=1
            fi
        done <<< "$mx_records"
    fi

    if [[ $found_mx -eq 0 ]]; then
        echo -e "    ${RED}No mail servers found${NC}"
    fi

    # 3. Historical DNS data
    echo -e "${BLUE}  [History] Historical DNS lookups:${NC}"
    echo -e "    ${YELLOW}Use external tools for historical data:${NC}"
    echo -e "    - SecurityTrails: ${CYAN}https://securitytrails.com/domain/${domain}/dns${NC}"
    echo -e "    - ViewDNS: ${CYAN}https://viewdns.info/iphistory/?domain=${domain}${NC}"
    echo -e "    - DNSlytics: ${CYAN}https://dnslytics.com/domain/${domain}${NC}"

    # 4. Check DNS records from different nameservers
    echo -e "${BLUE}  [DNS] Checking alternative nameservers:${NC}"
    local nameservers=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")
    local found_alt=0

    for ns in "${nameservers[@]}"; do
        local alt_ip
        alt_ip=$(dig @"$ns" +short a "$domain" 2>/dev/null | head -1)

        if [[ -n "$alt_ip" ]] && [[ "$alt_ip" != "$a_record" ]]; then
            echo -e "    ${GREEN}${ns} -> $alt_ip${NC}"
            found_alt=1
        fi
    done

    if [[ $found_alt -eq 0 ]]; then
        echo -e "    ${RED}No alternative records found${NC}"
    fi

    # 5. SSL certificate analysis
    echo -e "${BLUE}  [SSL] Certificate analysis:${NC}"
    echo -e "    ${YELLOW}Use external tools for SSL analysis:${NC}"
    echo -e "    - Censys: ${CYAN}https://search.censys.io/search?q=${domain}${NC}"
    echo -e "    - CRT.sh: ${CYAN}https://crt.sh/?q=${domain}${NC}"
    echo -e "    - SSLMate: ${CYAN}https://sslmate.com/certspotter/api/${domain}${NC}"

    echo -e "${PURPLE}  [Note] Cloudflare bypass requires manual verification of discovered IPs${NC}"
}

# DDoS Guard bypass detection and techniques
bypass_ddos_guard() {
    local domain="$1"
    echo -e "${CYAN}[*] DDoS Guard Bypass Techniques: ${YELLOW}$domain${NC}"

    # Known DDoS Guard IP ranges
    local ddos_guard_ranges=(
        "195.133.0.0/16"
        "185.174.136.0/22"
        "91.204.176.0/22"
        "91.204.180.0/22"
        "91.204.184.0/22"
    )

    local is_ddos_guard=0
    local a_record
    a_record=$(dig +short a "$domain" 2>/dev/null | head -1)

    if [[ -n "$a_record" ]]; then
        # Check if IP belongs to DDoS Guard network
        for range in "${ddos_guard_ranges[@]}"; do
            if ip_in_range "$a_record" "$range"; then
                is_ddos_guard=1
                echo -e "${RED}  [DDoS Guard] IP $a_record belongs to DDoS Guard network${NC}"
                break
            fi
        done
    fi

    # Check for DDoS Guard nameservers
    local ns_result
    ns_result=$(dig +short ns "$domain" 2>/dev/null)
    if echo "$ns_result" | grep -qi "ddos-guard"; then
        is_ddos_guard=1
        echo -e "${RED}  [DDoS Guard] Domain protected by DDoS Guard DNS${NC}"
    fi

    if [[ $is_ddos_guard -eq 0 ]]; then
        echo -e "${GREEN}  [Status] No DDoS Guard protection detected${NC}"
        return
    fi

    echo -e "${PURPLE}  [Bypass Methods] Trying to discover real IP:${NC}"

    # 1. Check specialized subdomains
    echo -e "${BLUE}  [DNS] Checking specialized subdomains:${NC}"
    local subdomains=("origin" "direct" "ns1" "ns2" "mail" "smtp" "server" "host" "static" "assets")
    local found_subdomain=0

    for sub in "${subdomains[@]}"; do
        local full_sub="${sub}.${domain}"
        local sub_ip
        sub_ip=$(dig +short a "$full_sub" 2>/dev/null | head -1)

        if [[ -n "$sub_ip" ]]; then
            # Skip DDoS Guard IPs
            local is_ddos_ip=0
            for range in "${ddos_guard_ranges[@]}"; do
                if ip_in_range "$sub_ip" "$range"; then
                    is_ddos_ip=1
                    break
                fi
            done

            if [[ $is_ddos_ip -eq 0 ]]; then
                echo -e "    ${GREEN}$full_sub -> $sub_ip${NC}"
                found_subdomain=1
            fi
        fi
    done

    if [[ $found_subdomain -eq 0 ]]; then
        echo -e "    ${RED}No revealing subdomains found${NC}"
    fi

    # 2. Check MX records
    echo -e "${BLUE}  [MX] Mail server records:${NC}"
    local mx_records
    mx_records=$(dig +short mx "$domain" 2>/dev/null)
    local found_mx=0

    if [[ -n "$mx_records" ]]; then
        while read -r priority record; do
            local mx_ip
            mx_ip=$(dig +short a "$record" 2>/dev/null | head -1)
            if [[ -n "$mx_ip" ]]; then
                # Check if MX IP is not DDoS Guard
                local is_ddos_ip=0
                for range in "${ddos_guard_ranges[@]}"; do
                    if ip_in_range "$mx_ip" "$range"; then
                        is_ddos_ip=1
                        break
                    fi
                done

                if [[ $is_ddos_ip -eq 0 ]]; then
                    echo -e "    ${GREEN}$record -> $mx_ip (Priority: $priority)${NC}"
                    found_mx=1
                fi
            fi
        done <<< "$mx_records"
    fi

    if [[ $found_mx -eq 0 ]]; then
        echo -e "    ${RED}No revealing mail servers found${NC}"
    fi

    # 3. Historical DNS data
    echo -e "${BLUE}  [History] Historical DNS lookups:${NC}"
    echo -e "    ${YELLOW}Use external tools for historical data:${NC}"
    echo -e "    - SecurityTrails: ${CYAN}https://securitytrails.com/domain/${domain}/dns${NC}"
    echo -e "    - ViewDNS: ${CYAN}https://viewdns.info/iphistory/?domain=${domain}${NC}"
    echo -e "    - DNSlytics: ${CYAN}https://dnslytics.com/domain/${domain}${NC}"

    # 4. Check DNS records from different nameservers
    echo -e "${BLUE}  [DNS] Checking alternative nameservers:${NC}"
    local nameservers=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222" "84.200.69.80")
    local found_alt=0

    for ns in "${nameservers[@]}"; do
        local alt_ip
        alt_ip=$(dig @"$ns" +short a "$domain" 2>/dev/null | head -1)

        if [[ -n "$alt_ip" ]] && [[ "$alt_ip" != "$a_record" ]]; then
            # Check if alternative IP is not DDoS Guard
            local is_ddos_ip=0
            for range in "${ddos_guard_ranges[@]}"; do
                if ip_in_range "$alt_ip" "$range"; then
                    is_ddos_ip=1
                    break
                fi
            done

            if [[ $is_ddos_ip -eq 0 ]]; then
                echo -e "    ${GREEN}${ns} -> $alt_ip${NC}"
                found_alt=1
            fi
        fi
    done

    if [[ $found_alt -eq 0 ]]; then
        echo -e "    ${RED}No alternative records found${NC}"
    fi

    # 5. Check for domain fronting opportunities
    echo -e "${BLUE}  [Domain Fronting] Possible fronting techniques:${NC}"
    echo -e "    ${YELLOW}1. Cloudflare fronting:${NC}"
    echo -e "       curl -H \"Host: ${domain}\" https://cloudflare.com"
    echo -e "    ${YELLOW}2. AWS CloudFront fronting:${NC}"
    echo -e "       curl -H \"Host: ${domain}\" https://d111111abcdef8.cloudfront.net"
    echo -e "    ${YELLOW}3. Google Cloud CDN fronting:${NC}"
    echo -e "       curl -H \"Host: ${domain}\" https://storage.googleapis.com"

    echo -e "${PURPLE}  [Note] DDoS Guard bypass requires manual verification of discovered IPs${NC}"
}

# DNS records lookup without TXT records
get_dns() {
    local target="$1"
    echo -e "${CYAN}[*] DNS records: ${YELLOW}$target${NC}"

    local has_records=0

    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Reverse DNS for IP
        echo -e "${BLUE}  [PTR] Reverse DNS:${NC}"
        local ptr_result
        ptr_result=$(dig +short -x "$target" 2>/dev/null)
        if [ -z "$ptr_result" ]; then
            echo -e "${RED}    not found${NC}"
        else
            echo "    $ptr_result"
            has_records=1
        fi
    else
        # Domain records (without TXT)
        echo -e "${BLUE}  [A] IPv4 addresses:${NC}"
        local a_result
        a_result=$(dig +short a "$target" 2>/dev/null)
        if [ -z "$a_result" ]; then
            echo -e "${RED}    not found${NC}"
        else
            echo "    $a_result"
            has_records=1
        fi

        echo -e "${BLUE}  [AAAA] IPv6 addresses:${NC}"
        local aaaa_result
        aaaa_result=$(dig +short aaaa "$target" 2>/dev/null)
        if [ -z "$aaaa_result" ]; then
            echo -e "${RED}    not found${NC}"
        else
            echo "    $aaaa_result"
            has_records=1
        fi

        echo -e "${BLUE}  [MX] Mail servers:${NC}"
        local mx_result
        mx_result=$(dig +short mx "$target" 2>/dev/null | sort -n)
        if [ -z "$mx_result" ]; then
            echo -e "${RED}    not found${NC}"
        else
            echo "    $mx_result" | sed 's/^/    /'
            has_records=1
        fi

        # TXT records removed for domains
    fi

    # NS records for both IP and domains
    echo -e "${BLUE}  [NS] DNS servers:${NC}"
    local ns_result
    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # For IPs, get NS of the domain from PTR
        local ptr_domain=$(dig +short -x "$target" 2>/dev/null | sed 's/\.$//')
        if [ -n "$ptr_domain" ]; then
            ns_result=$(dig +short ns "$ptr_domain" 2>/dev/null | sort | uniq)
        fi
    else
        # For domains, direct NS lookup
        ns_result=$(dig +short ns "$target" 2>/dev/null | sort | uniq)
    fi

    if [ -z "$ns_result" ]; then
        echo -e "${RED}    not found${NC}"
    else
        echo "$ns_result" | sed 's/^/    /'
        has_records=1
    fi

    # Cloudflare bypass for domains
    if [[ ! $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local is_cloudflare=0

        # Check NS for cloudflare
        if echo "$ns_result" | grep -qi "cloudflare"; then
            is_cloudflare=1
        fi

        # Check A record for Cloudflare IPs
        if [[ -n "$a_result" ]]; then
            for ip in $a_result; do
                if [[ $ip =~ ^(173\.245\.4[8-9]|173\.245\.5[0-9]|173\.245\.6[0-3]|103\.21\.24[4-7]|103\.22\.20[0-3]) ]]; then
                    is_cloudflare=1
                    break
                fi
            done
        fi

        if [[ $is_cloudflare -eq 1 ]]; then
            bypass_cloudflare "$target"
        fi

        # DDoS Guard detection
        local is_ddos_guard=0

        # Check NS for DDoS Guard
        if echo "$ns_result" | grep -qi "ddos-guard"; then
            is_ddos_guard=1
        fi

        # Check A record for DDoS Guard IPs
        local ddos_guard_ranges=(
            "195.133.0.0/16"
            "185.174.136.0/22"
            "91.204.176.0/22"
            "91.204.180.0/22"
            "91.204.184.0/22"
        )

        if [[ -n "$a_result" ]]; then
            for ip in $a_result; do
                for range in "${ddos_guard_ranges[@]}"; do
                    if ip_in_range "$ip" "$range"; then
                        is_ddos_guard=1
                        break 2
                    fi
                done
            done
        fi

        if [[ $is_ddos_guard -eq 1 ]]; then
            bypass_ddos_guard "$target"
        fi
    fi

    if [ $has_records -eq 0 ]; then
        echo -e "${RED}  [!] No DNS records found${NC}"
    fi
    echo
}

# Detailed DNS analysis without TXT records
run_nslookup() {
    echo -e "${CYAN}[*] Detailed DNS analysis (nslookup): ${YELLOW}$1${NC}"

    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Reverse DNS for IP
        echo -e "${BLUE}  [PTR] Reverse DNS:${NC}"
        nslookup "$1" | awk '/name =/{print "    " $NF}' | sed 's/\.$//' | sort | uniq
    else
        # Domain records (without TXT)
        echo -e "${BLUE}  [A] IPv4 addresses:${NC}"
        nslookup -type=A "$1" | awk '/Address/{if (NR>2) print "    " $NF}'

        echo -e "${BLUE}  [AAAA] IPv6 addresses:${NC}"
        nslookup -type=AAAA "$1" | awk '/has AAAA/{print "    " $NF}'

        echo -e "${BLUE}  [MX] Mail servers:${NC}"
        nslookup -type=MX "$1" | awk '/mail exchanger/{print "    " $6 " (priority: " $5 ")"}' | sort -n

        # TXT records removed for domains

        echo -e "${BLUE}  [NS] DNS servers:${NC}"
        nslookup -type=NS "$1" | awk '/nameserver/{print "    " $NF}' | sort
    fi
    echo
}

# IP information lookup with better ASN handling
get_ip_info() {
    local target="$1"
    local ip

    if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip="$target"
    else
        ip=$(dig +short a "$target" | head -1 2>/dev/null)
        if [ -z "$ip" ]; then
            echo -e "${RED}  [!] Failed to get IP for geolocation and ASN lookup${NC}"
            return
        fi
    fi

    echo -e "${CYAN}[*] IP information: ${YELLOW}$ip${NC}"

    local response
    response=$(curl -s "https://ipinfo.io/$ip/json")

    if [ $? -ne 0 ]; then
        echo -e "${RED}  [!] Error querying ipinfo.io API${NC}"
        return
    fi

    local country=$(echo "$response" | jq -r '.country // empty')
    local city=$(echo "$response" | jq -r '.city // empty')
    local org=$(echo "$response" | jq -r '.org // empty')
    local asn=$(echo "$response" | jq -r '.asn // empty')
    local hostname=$(echo "$response" | jq -r '.hostname // empty')

    # Extract ASN number from org field if needed
    if [ -z "$asn" ] && [ -n "$org" ]; then
        asn=$(echo "$org" | grep -o 'AS[0-9]\+')
    fi

    if [ -n "$country" ]; then
        echo -e "${GREEN}  Country:    $country${NC}"
    else
        echo -e "${RED}  Country:    not detected${NC}"
    fi

    if [ -n "$city" ]; then
        echo -e "${GREEN}  City:       $city${NC}"
    else
        echo -e "${RED}  City:       not detected${NC}"
    fi

    if [ -n "$hostname" ]; then
        echo -e "${GREEN}  Hostname:   $hostname${NC}"
    fi

    if [ -n "$asn" ]; then
        echo -e "${GREEN}  ASN:        $asn${NC}"
    else
        echo -e "${RED}  ASN:        not found${NC}"
    fi

    if [ -n "$org" ]; then
        # Clean organization name from ASN prefix
        local clean_org=$(echo "$org" | sed 's/^AS[0-9]\+\s*//')
        echo -e "${GREEN}  Organization: $clean_org${NC}"
    else
        echo -e "${RED}  Organization: not found${NC}"
    fi

    # Additional ASN information
    if [ -n "$asn" ]; then
        local asn_num=$(echo "$asn" | grep -o 'AS[0-9]\+' | head -1)
        if [ -n "$asn_num" ]; then
            echo -e "\n${BLUE}  [ASN Details] Autonomous system information:${NC}"
            if [ "$OS" = "termux" ]; then
                whois "$asn_num" | grep -Ei "aut-num|as-name|descr|org-name|country" | head -5
            else
                whois -H "$asn_num" | grep -Ei "aut-num|as-name|descr|org-name|country" | head -5
            fi
        fi
    fi

    echo
}

# Function to remove ANSI escape sequences
remove_ansi_sequences() {
    sed -e 's/\x1b\[[0-9;]*m//g' -e 's/\x1b\[[0-9;]*[a-zA-Z]//g'
}

# Professional Nmap scanning function with enhanced vulnerability display
run_nmap() {
    local target="$1"
    local is_reachable="$2"
    local fast_scan="$3"
    local output_file="$4"

    echo -e "${CYAN}[*] Running Professional Nmap scan: ${YELLOW}$target${NC}"
    local options=""

    # Set timing template based on scan type
    if [ "$fast_scan" -eq 1 ]; then
        options+="-T5 "  # MAX speed for fast scans
        echo -e "${GREEN}  [+] Fast scan: Top 1000 ports with MAX speed (T5)${NC}"
        echo -e "${YELLOW}  [~] Estimated time: 1-5 minutes${NC}"
    else
        options+="-T4 "  # Aggressive for full scans
        echo -e "${GREEN}  [+] Comprehensive scan: All 65535 ports${NC}"
        echo -e "${YELLOW}  [~] Estimated time: 10-30 minutes${NC}"
    fi

    options+="-sV --open --min-hostgroup 64"

    # Add OS detection if running as root
    if [ "$(id -u)" = "0" ]; then
        options+=" -O"
        echo -e "${GREEN}  [+] OS detection enabled (running as root)${NC}"
    else
        echo -e "${YELLOW}  [!] OS detection requires root privileges. Skipping OS detection.${NC}"
    fi

    # Choose scanning method based on privileges
    if [ "$(id -u)" = "0" ]; then
        options+=" -sS --min-rate 1000"
        echo -e "${GREEN}  [+] Using SYN scan (privileged mode) with min-rate 1000 packets/sec${NC}"
    else
        options+=" -sT --min-rate 500"
        echo -e "${YELLOW}  [!] Using TCP connect scan (unprivileged mode) with min-rate 500 packets/sec${NC}"
    fi

    # Set port range based on scan type
    if [ "$fast_scan" -eq 1 ]; then
        options+=" --top-ports 1000"
    else
        options+=" -p-"
    fi

    # Add vulnerability scanning if script is available
    local vulners_script=""
    if [ "$OS" = "termux" ]; then
        vulners_script="/data/data/com.termux/files/usr/share/nmap/scripts/vulners.nse"
    else
        vulners_script="/usr/share/nmap/scripts/vulners.nse"
    fi

    if [ -f "$vulners_script" ]; then
        options+=" --script=vulners.nse"
        echo -e "${GREEN}  [+] Vulnerability scanning with vulners.nse enabled${NC}"
    else
        echo -e "${YELLOW}  [!] Vulnerability scanning script not found. To install:${NC}"
        echo -e "${YELLOW}      curl -s https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse > '$vulners_script'${NC}"
    fi

    # Add output formats if output file is specified
    local output_options=""
    if [ -n "$output_file" ]; then
        output_options="-oN $output_file"
        echo -e "${GREEN}  [+] Saving full results to: ${YELLOW}$output_file${NC}"
    fi

    local temp_file
    if [ "$OS" = "termux" ]; then
        temp_file=$(mktemp -p /data/data/com.termux/files/usr/tmp)
    else
        temp_file=$(mktemp)
    fi

    echo -e "${BLUE}  [CMD] nmap $options $output_options $target${NC}"

    # Run nmap and capture output
    nmap $options $output_options "$target" > "$temp_file" 2>&1
    local nmap_exit=$?

    if [ $nmap_exit -ne 0 ]; then
        echo -e "${RED}  [!] Nmap execution error!${NC}"
        echo -e "${YELLOW}  [ERROR DETAILS]${NC}"
        # Clean error output
        remove_ansi_sequences < "$temp_file" | head -n 10
        rm "$temp_file"
        return
    fi

    # Clean the output
    local clean_file="${temp_file}_clean"
    remove_ansi_sequences < "$temp_file" > "$clean_file"

    # Process and display open ports
    echo -e "\n${PURPLE}  [*] Open Ports Summary:${NC}"
    if grep -q "open" "$clean_file"; then
        # Print table header
        echo -e "${CYAN}PORT      STATE  SERVICE        VERSION${NC}"
        echo -e "----------------------------------------"

        # Define critical services
        critical_services=(
            ssh ftp telnet smtp microsoft-ds netbios netbios-ssn ms-wbt-server
            snmp pop3 imap mysql vnc
        )

        # Extract and format open ports with color coding
        grep "open" "$clean_file" | while read -r line; do
            # Remove any remaining special characters
            clean_line=$(echo "$line" | tr -cd '\11\12\15\40-\176')

            port_field=$(echo "$clean_line" | awk '{print $1}')
            port_num=$(echo "$port_field" | cut -d'/' -f1)
            state=$(echo "$clean_line" | awk '{print $2}')
            service=$(echo "$clean_line" | awk '{print $3}')
            version=$(echo "$clean_line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}' | sed 's/ $//')

            # Highlight critical services
            if [[ " ${critical_services[@]} " =~ " $service " ]]; then
                service_color="${RED}"
            else
                service_color="${GREEN}"
            fi

            # Выводим порт и состояние без цвета, сервис - с цветом
            printf "%-9s ${GREEN}%-6s ${service_color}%-14s ${NC}%s\n" \
                   "$port_field" "$state" "$service" "$version"
        done
    else
        echo -e "${RED}  [!] No open ports found${NC}"
    fi

    # Show OS detection results if available
    if grep -q "OS details" "$clean_file"; then
        echo -e "\n${PURPLE}  [*] OS Detection Results:${NC}"
        grep "OS details" "$clean_file" | cut -d: -f2 | sed 's/^ *//; s/  */ /g' | sed 's/^/  /'
    fi

    # Show security note summary
    if grep -q "open" "$clean_file"; then
        echo -e "\n${PURPLE}  [*] Security Note Summary:${NC}"
        grep "open" "$clean_file" | while read -r line; do
            clean_line=$(echo "$line" | tr -cd '\11\12\15\40-\176')
            service=$(echo "$clean_line" | awk '{print $3}')

            # Check if service is in critical list
            if [[ " ${critical_services[@]} " =~ " $service " ]]; then
                port=$(echo "$clean_line" | awk '{print $1}')
                version=$(echo "$clean_line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}')
                echo -e "${RED}  [!] Security-critical service on $port: ${service} - ${version}${NC}"
            fi
        done
    fi

    # Enhanced vulnerability findings with RCE highlighting
    if grep -q "vulners" "$clean_file"; then
        echo -e "\n${PURPLE}  [*] Vulnerability Findings:${NC}"

        # Extract and format vulnerabilities
        grep -A 6 "vulners" "$clean_file" | while IFS= read -r line; do
            # Skip unwanted lines
            if echo "$line" | grep -qE "https://|^$"; then
                continue
            fi

            # Remove special characters and trim spaces
            clean_line=$(echo "$line" | sed -e 's/|//g' -e 's/^ *//' -e 's/ *$//')

            # Skip empty lines
            if [ -z "$clean_line" ]; then
                continue
            fi

            # Check for RCE (Remote Code Execution) specifically
            if echo "$clean_line" | grep -qi "remote code execution"; then
                # Highlight RCE vulnerabilities in red
                echo -e "  ${RED}[RCE] ${clean_line}${NC}"
                continue
            fi

            # Color coding by severity
            if echo "$clean_line" | grep -qi "critical"; then
                color="${RED}"
            elif echo "$clean_line" | grep -qi "high"; then
                color="${ORANGE}"
            elif echo "$clean_line" | grep -qi "medium"; then
                color="${YELLOW}"
            elif echo "$clean_line" | grep -qi "low"; then
                color="${GREEN}"
            elif echo "$clean_line" | grep -q "CVE-"; then
                # Default color for CVE without explicit severity
                color="${CYAN}"
            else
                color="${NC}"
            fi

            # Format CVE IDs specifically
            if echo "$clean_line" | grep -q "CVE-"; then
                # Extract CVE ID and description
                cve_id=$(echo "$clean_line" | grep -o 'CVE-[0-9]\{4\}-[0-9]\+')
                cve_desc=$(echo "$clean_line" | sed "s/$cve_id//")

                # Print with special formatting
                echo -e "  ${color}[${cve_id}]${NC} ${cve_desc}"
            else
                # Print normal vulnerability lines
                echo -e "  ${color}${clean_line}${NC}"
            fi
        done

        # Add note about RCE vulnerabilities
        echo -e "\n${RED}  [*] RCE = Remote Code Execution (extremely critical)${NC}"
    fi

    rm -f "$temp_file" "$clean_file"
}

# Main function
main() {
    # Parse command line arguments
    local target=""
    local fast_scan=0
    local output_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -v|--version)
                show_version
                ;;
            -f|--fast)
                fast_scan=1
                shift
                ;;
            -o|--output)
                if [ -n "$2" ]; then
                    output_file="$2"
                    shift 2
                else
                    error "Output file not specified"
                    exit 1
                fi
                ;;
            *)
                if [ -z "$target" ]; then
                    target="$1"
                else
                    error "Multiple targets specified"
                    show_help
                    exit 1
                fi
                shift
                ;;
        esac
    done

    clear

    # Ultra-minimalist banner for Termux
    echo -e "${GREEN}╔══════════════════╗"
    echo -e "║ NetScan ${BLUE}v1.3${GREEN} ║"
    echo -e "╚══════════════════╝${NC}"
    echo -e "OS: ${YELLOW}$OS${NC}"
    echo -e "Scan: ${YELLOW}$([ "$fast_scan" -eq 1 ] && echo "Fast" || echo "Full")${NC}"
    [ -n "$output_file" ] && echo -e "Output: ${YELLOW}$output_file${NC}"
    echo -e "Target: ${YELLOW}${target:-"Not specified"}${NC}"

    check_dependencies

    if [ -z "$target" ]; then
        echo -n "Enter target (IP/domain): "
        read target
    fi

    if [ -z "$target" ]; then
        error "No target specified"
        show_help
        exit 1
    fi

    target=$(echo "$target" | sed -e 's|^http://||' -e 's|^https://||' -e 's|^ftp://||' -e 's|/.*$||')

    if [[ ! "$target" =~ ^([0-9a-zA-Z-]+\.)+[a-zA-Z]{2,}$ ]] &&
       [[ ! "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error "Invalid target format"
        exit 1
    fi

    echo -e "\n${YELLOW}▄ Starting professional scan: $target ▄${NC}\n"

    # Check host status once and store the result
    if check_host "$target"; then
        is_reachable=0
    else
        is_reachable=1
        echo -e "${YELLOW}[!] Host not responding to ping, continuing with scan...${NC}"
    fi

    get_whois "$target"
    get_dns "$target"
    run_nslookup "$target"
    get_ip_info "$target"
    run_nmap "$target" $is_reachable $fast_scan "$output_file"

    echo -e "\n${GREEN}✓ Professional scan completed!${NC}"

    if [ -n "$output_file" ]; then
        echo -e "${CYAN}Full results saved to: ${YELLOW}$output_file${NC}"
    fi
}

main "$@"
