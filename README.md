# Cloudflare Detection & IP Resolver

## Overview
This auxiliary module scans a list of domains, resolves their IP addresses, and detects whether Cloudflare protects them.

## Features
- Reads a list of domains from a file
- Resolves IP addresses for each domain
- Detects if a domain is using Cloudflare
- Saves results to an output file (optional)

## Requirements
- Metasploit Framework
- Ruby environment

## Installation
1. move the `cloudflare_scanner.rb` script to the Metasploit module directory:
   ```bash
   sudo mv cloudflare_scanner.rb ~/.msf4/modules/auxiliary/scanner/
   ```
2. Start Metasploit Framework:
   ```bash
   msfconsole
   ```
3. Load the module:
   ```bash
   use auxiliary/scanner/cloudflare_scanner
   ```

## Usage
1. Set the required options:
   ```bash
   set DOMAIN_LIST /path/to/domains.txt
   ```
2. (Optional) Set an output file:
   ```bash
   set OUTPUT_FILE /path/to/results.txt
   ```
3. Run the scan:
   ```bash
   run
   ```

## Output Format
Example output:
```
[*] Scanning: example.com
[+] example.com, IP: 192.0.2.1, Cloudflare: Yes
[*] Scanning: test.com
[+] test.com, IP: 203.0.113.2, Cloudflare: No
[+] Results saved to results.txt
[*] Scan completed.
```

## How It Works
- The script removes `http://` and `https://` from domain names.
- It resolves the IP address of each domain using `Resolve`.
- It sends an HTTP request to check if the response contains the `cf-ray` header, indicating Cloudflare protection.
- Results are displayed in the console and optionally saved to a file.

## Disclaimer
This tool is intended for **ethical security research**. You can use it only on domains you have permission to scan.


