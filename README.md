# Advanced Bug Bounty Recon Automation Tool

## Description

The Advanced Bug Bounty Recon Automation Tool is a comprehensive Bash script designed to automate various bug bounty reconnaissance tasks. The tool integrates a wide range of open-source utilities to streamline the process of subdomain enumeration, URL fetching, vulnerability scanning, and more. With enhanced user experience features like colors, logging, and interactive menus, this tool aims to make bug bounty recon efficient and user-friendly.

## Features

- Combined Subdomain Enumeration (using subfinder, assetfinder, amass)
- Fetching URLs from live subdomains using multiple methods
- Searching for sensitive files in fetched URLs
- Hidden parameter detection (using Arjun)
- CORS check (using corsy.py)
- Wordpress aggressive scan
- LFI testing
- Directory brute-force (using ffuf and dirsearch)
- JS file hunting
- Subdomain takeover check
- Header-based blind XSS testing
- Blind XSS testing
- SQL Injection testing
- Network scanning

## Installation

### Prerequisites

Ensure the following tools are installed and available in your PATH:

- subfinder
- assetfinder
- amass
- httpx-toolkit
- katana `(v1.1.0)`
- gau
- gf
- urldedupe
- anew
- arjun
- wpscan
- ffuf
- qsreplace
- bxss
- naabu
- nmap
- masscan
- subzy
- dirsearch
- jsleak
- jsecret
- ghauri
- sqlmap
- corsy.py
- curl
- sed
- grep
- sort
- figlet (optional)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/bug-bounty-recon-tool.git
   cd bug-bounty-recon-tool
   ```

2. Make the script executable:
   ```bash
   chmod +x recon.sh
   ```

3. Run the script:
   ```bash
   ./recon.sh
   ```

## Usage

### Main Menu

Upon running the script, you will be presented with a main menu offering various options:

1. Combined Subdomain Enumeration
2. Fetch URLs from Live Subdomains (→ final_urls.txt)
3. Search for Sensitive Files
4. Hidden Parameter Detection (Arjun)
5. CORS Check
6. Wordpress Aggressive Scan
7. LFI Testing
8. Directory Bruteforce
9. JS File Hunting
10. Subdomain Takeover Check
11. Header Based Blind XSS Testing
12. Blind XSS Testing
13. SQL Injection Testing
14. Network Scanning Options
15. Help
16. Exit

### Example Commands

#### Combined Subdomain Enumeration

This option combines subfinder, assetfinder, and amass to discover subdomains and filters live ones using httpx-toolkit.

#### Fetch URLs from Live Subdomains

Combines multiple methods (Katana, gau, etc.) to generate a final list of URLs from live subdomains, saved in `output/final_urls.txt`.

#### Search for Sensitive Files

Searches for sensitive files (e.g., .xls, .sql, .json) in the URLs fetched from live subdomains.

#### Hidden Parameter Detection

Uses Arjun to detect hidden parameters in the URLs listed in `output/final_urls.txt`.

#### CORS Check

Uses corsy.py to check for CORS misconfigurations in the subdomains.

#### Wordpress Aggressive Scan

Performs an aggressive scan on Wordpress sites using wpscan.

#### LFI Testing

Tests endpoints from `output/final_urls.txt` for Local File Inclusion (LFI) vulnerabilities.

#### Directory Bruteforce

Offers both ffuf and dirsearch methods to brute-force directories on a selected domain.

#### JS File Hunting

Extracts JavaScript file URLs from `output/final_urls.txt` and scans them using nuclei, jsleak, and jsecret.

#### Subdomain Takeover Check

Checks live subdomains for takeover vulnerabilities using subzy.

#### Header Based Blind XSS Testing

Tests for XSS via header injection on endpoints from `output/final_urls.txt`.

#### Blind XSS Testing

Tests for blind XSS via parameter injection on endpoints from `output/final_urls.txt`.

#### SQL Injection Testing

Tests endpoints from `output/final_urls.txt` for SQL injection vulnerabilities using ghauri or sqlmap.

#### Network Scanning Options

Offers network scanning options using Naabu, Nmap, or Masscan.

## Dependencies

This tool relies on various open-source utilities. Ensure all required tools are installed and available in your PATH. Refer to the "Prerequisites" section for the list of required tools.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```` ▋
