
##
##   Hackzy  -  Simple multi-tool for ethical hacking and learning about computers
##   Author  :  Cr3zy
##   Version :  2.0.0
##   GitHub  :  https://github.com/Cr3zy-dev
##
##   This program is free software: you can redistribute it and/or modify
##   it under the terms of the GNU General Public License as published by
##   the Free Software Foundation, either version 3 of the License, or
##   (at your option) any later version.
##
##   This program is distributed in the hope that it will be useful,
##   but WITHOUT ANY WARRANTY; without even the implied warranty of
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
##   GNU General Public License for more details.
##
##   You should have received a copy of the GNU General Public License
##   along with this program. If not, see <https://www.gnu.org/licenses/>.
##
##   Copyright (C) 2025  Cr3zy
##

# Check dependencies
required_modules = ['colorama', 'whois', 'requests', 'phonenumbers', 'user_agents', 'PIL']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print("\n [!] Missing required modules:")
    for m in missing_modules:
        print(f"    - {m}")
    print("\n Please install them manually using pip, e.g.:\n")
    print("    pip install " + ' '.join(missing_modules))
    input("\n Press Enter to exit...")
    exit()

# imports
import os
import sys
import time
import socket
import json
import urllib.request
import re
import requests
from colorama import Fore, Style, init
from PIL import Image
from PIL.ExifTags import TAGS
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import whois
from user_agents import parse

init(autoreset=True)

# Cross-platform press-any-key
def wait_for_keypress():
    print(f"{MENU_COLOR} Press any key to continue...", end='', flush=True)
    try:
        import msvcrt
        msvcrt.getch()
    except ImportError:
        import tty
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

# Clear screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Port Scanner Logic
def run_port_scanner():
    clear()
    target = input(f"{Fore.WHITE} Enter IP address or domain to scan (e.g., example.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Scanning ports 1-100 on {target}...\n")
    open_ports = []
    for port in range(1, 101):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.WHITE} [{MENU_COLOR}OPEN{Fore.WHITE}] Port {port}")
            open_ports.append(port)
        sock.close()
    if not open_ports:
        print(f"\n{MENU_COLOR} No open ports found.")
    else:
        print(f"\n{Fore.WHITE} Scan complete. {MENU_COLOR}{len(open_ports)} open port(s) found.")
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Port Scanner UI
def port_scanner_screen():
    clear()
    print(MENU_COLOR + r"""
  _____           _      _____                                 
 |  __ \         | |    / ____|                                
 | |__) |__  _ __| |_  | (___   ___ __ _ _ __  _ __   ___ _ __ 
 |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |  | (_) | |  | |_   ____) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|_| |_|\___|_|   
    """)
    print(Fore.WHITE + """ A port scanner is a tool used to detect open ports and services available
 on a target machine. This helps to identify possible entry points that
 could be vulnerable or useful in a network analysis.

 Only use this tool on systems you own or have permission to analyze.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Port Scanner")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")
    
    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_port_scanner()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        port_scanner_screen()

import json
import urllib.request

# IP Tracker Logic
def run_ip_tracker():
    clear()
    target_ip = input(f"{Fore.WHITE} Enter IP address to track: {Fore.GREEN}")
    print(f"{MENU_COLOR} Fetching info for {target_ip}...\n")
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{target_ip}") as response:
            data = json.load(response)
            if data['status'] == 'success':
                print(f"{MENU_COLOR} IP Address: {Fore.WHITE}{data['query']}")
                print(f"{MENU_COLOR} Country:    {Fore.WHITE}{data['country']} ({data['countryCode']})")
                print(f"{MENU_COLOR} Region:     {Fore.WHITE}{data['regionName']}")
                print(f"{MENU_COLOR} City:       {Fore.WHITE}{data['city']}")
                print(f"{MENU_COLOR} ISP:        {Fore.WHITE}{data['isp']}")
                print(f"{MENU_COLOR} Org:        {Fore.WHITE}{data['org']}")
                print(f"{MENU_COLOR} Lat/Lon:    {Fore.WHITE}{data['lat']}, {data['lon']}")
                print(f"{MENU_COLOR} Timezone:   {Fore.WHITE}{data['timezone']}")
            else:
                print(f"{MENU_COLOR} Failed to fetch data. Reason: {data['message']}")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# IP Tracker UI
def ip_tracker_screen():
    clear()
    print(MENU_COLOR + r"""
  _____ _____    _______             _             
 |_   _|  __ \  |__   __|           | |            
   | | | |__) |    | |_ __ __ _  ___| | _____ _ __ 
   | | |  ___/     | | '__/ _` |/ __| |/ / _ \ '__|
  _| |_| |         | | | | (_| | (__|   <  __/ |   
 |_____|_|         |_|_|  \__,_|\___|_|\_\___|_|                                            
    """)
    print(Fore.WHITE + """ IP Tracker gathers basic information about an IP address such as
 country, region, city, ISP, and more using public APIs.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run IP Tracker")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")
    
    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_ip_tracker()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        ip_tracker_screen()

# Whois Lookup Logic
def run_whois_lookup():
    clear()
    domain = input(f"{Fore.WHITE} Enter domain to lookup (e.g., example.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Fetching WHOIS data for {domain}...\n")
    try:
        w = whois.whois(domain)
        print(f"{MENU_COLOR} Domain Name:   {Fore.WHITE}{w.domain_name}")
        print(f"{MENU_COLOR} Registrar:     {Fore.WHITE}{w.registrar}")
        print(f"{MENU_COLOR} Creation Date: {Fore.WHITE}{w.creation_date}")
        print(f"{MENU_COLOR} Expiration:    {Fore.WHITE}{w.expiration_date}")
        print(f"{MENU_COLOR} Name Servers:  {Fore.WHITE}{w.name_servers}")
        print(f"{MENU_COLOR} Emails:        {Fore.WHITE}{w.emails}")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Whois Lookup UI
def whois_lookup_screen():
    clear()
    print(MENU_COLOR + r"""
 __          ___           _       _                 _                
 \ \        / / |         (_)     | |               | |               
  \ \  /\  / /| |__   ___  _ ___  | |     ___   ___ | | ___   _ _ __  
   \ \/  \/ / | '_ \ / _ \| / __| | |    / _ \ / _ \| |/ / | | | '_ \ 
    \  /\  /  | | | | (_) | \__ \ | |___| (_) | (_) |   <| |_| | |_) |
     \/  \/   |_| |_|\___/|_|___/ |______\___/ \___/|_|\_\\__,_| .__/ 
                                                               | |    
                                                               |_|    
    """)
    print(Fore.WHITE + """ Whois Lookup allows you to fetch domain registration data from public records.
 This includes registrar info, creation/expiration dates, and nameservers.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Whois Lookup")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_whois_lookup()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        whois_lookup_screen()

# DNS Resolver Logic
def run_dns_resolver():
    clear()
    domain = input(f"{Fore.WHITE} Enter domain to resolve (e.g., google.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Resolving {domain}...\n")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{MENU_COLOR} Resolved IP: {Fore.WHITE}{ip}")
    except socket.gaierror:
        print(f"{MENU_COLOR} Unable to resolve domain.")
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# DNS Resolver UI
def dns_resolver_screen():
    clear()
    print(MENU_COLOR + r"""
  _____  _   _  _____   _____                 _                
 |  __ \| \ | |/ ____| |  __ \               | |               
 | |  | |  \| | (___   | |__) |___  ___  ___ | |_   _____ _ __ 
 | |  | | . ` |\___ \  |  _  // _ \/ __|/ _ \| \ \ / / _ \ '__|
 | |__| | |\  |____) | | | \ \  __/\__ \ (_) | |\ V /  __/ |   
 |_____/|_| \_|_____/  |_|  \_\___||___/\___/|_| \_/ \___|_|    
    """)
    print(Fore.WHITE + """ DNS Resolver translates a domain name into its IP address.
 This is useful for checking where a domain points to.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run DNS Resolver")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_dns_resolver()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        dns_resolver_screen()

import re
import requests

# Email Scraper Logic
def run_email_scraper():
    clear()
    url = input(f"{Fore.WHITE} Enter URL to scrape emails from (e.g., https://example.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Scanning {url} for email addresses...\n")
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)
        found = list(set(emails))  # Remove duplicates
        if found:
            print(f"{MENU_COLOR} Found {len(found)} email address(es):\n")
            for email in found:
                print(f"{Fore.WHITE} - {email}")
        else:
            print(f"{MENU_COLOR} No emails found.")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

def email_scraper_screen():
    clear()
    print(MENU_COLOR + r"""
  ______                 _ _    _____                                
 |  ____|               (_) |  / ____|                               
 | |__   _ __ ___   __ _ _| | | (___   ___ _ __ __ _ _ __   ___ _ __ 
 |  __| | '_ ` _ \ / _` | | |  \___ \ / __| '__/ _` | '_ \ / _ \ '__|
 | |____| | | | | | (_| | | |  ____) | (__| | | (_| | |_) |  __/ |   
 |______|_| |_| |_|\__,_|_|_| |_____/ \___|_|  \__,_| .__/ \___|_|   
                                                    | |              
                                                    |_|              
    """)
    print(Fore.WHITE + """ Email Scraper extracts all email addresses from the given webpage using
 HTML content parsing and regular expressions.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Email Scraper")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_email_scraper()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        email_scraper_screen()

# Traceroute Logic
def run_traceroute():
    import subprocess
    clear()
    target = input(f"{Fore.WHITE} Enter domain or IP to trace route (e.g., example.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Tracing route to {target}...\n")
    try:
        if os.name == 'nt':
            # Windows
            result = subprocess.check_output(["tracert", target], text=True)
        else:
            # Linux / macOS
            result = subprocess.check_output(["traceroute", target], text=True)
        print(Fore.WHITE + result)
    except Exception as e:
        print(f"{MENU_COLOR} Error running traceroute: {e}")
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Traceroute UI
def traceroute_screen():
    clear()
    print(MENU_COLOR + r"""
  _______                                 _       
 |__   __|                               | |      
    | |_ __ __ _  ___ ___ _ __ ___  _   _| |_ ___ 
    | | '__/ _` |/ __/ _ \ '__/ _ \| | | | __/ _ \
    | | | | (_| | (_|  __/ | | (_) | |_| | ||  __/
    |_|_|  \__,_|\___\___|_|  \___/ \__,_|\__\___|
    """)
    print(Fore.WHITE + """ Traceroute reveals the path that data takes to reach a destination.
 Each line represents a 'hop' through a router or network node.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Traceroute")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_traceroute()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        traceroute_screen()

# Header Analyzer Logic
def run_header_analyzer():
    clear()
    url = input(f"{Fore.WHITE} Enter website URL (include http/https): {Fore.GREEN}")
    print(f"{MENU_COLOR} Fetching headers from {url}...\n")
    
    try:
        response = requests.get(url)
        headers = response.headers
        print(Fore.WHITE + " Headers:\n")
        for key, value in headers.items():
            print(f"{MENU_COLOR} {key}: {Fore.WHITE}{value}")
    except requests.exceptions.MissingSchema:
        print(f"{MENU_COLOR} Error: Invalid URL format. Please include http:// or https://")
    except requests.exceptions.ConnectionError:
        print(f"{MENU_COLOR} Error: Could not connect to the target.")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Header Analyzer UI
def header_analyzer_screen():
    clear()
    print(MENU_COLOR + r"""
  _    _                _                                  _                    
 | |  | |              | |               /\               | |                   
 | |__| | ___  __ _  __| | ___ _ __     /  \   _ __   __ _| |_   _ _______ _ __ 
 |  __  |/ _ \/ _` |/ _` |/ _ \ '__|   / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |  | |  __/ (_| | (_| |  __/ |     / ____ \| | | | (_| | | |_| |/ /  __/ |   
 |_|  |_|\___|\__,_|\__,_|\___|_|    /_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                                                              __/ |             
                                                             |___/              
    """)
    print(Fore.WHITE + """ Header Analyzer retrieves and displays HTTP response headers
 from a given URL. Useful for analyzing server behavior.\n""")
    
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Header Analyzer")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")
    
    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_header_analyzer()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        header_analyzer_screen()

import phonenumbers
from phonenumbers import geocoder, carrier, timezone

# Phone Info Lookup Logic
def run_phone_info_lookup():
    clear()
    number = input(f"{Fore.WHITE} Enter phone number with country code (e.g., +14155552671): {Fore.GREEN}")
    print(f"{MENU_COLOR} Analyzing phone number...\n")
    try:
        parsed = phonenumbers.parse(number)
        if not phonenumbers.is_valid_number(parsed):
            print(f"{MENU_COLOR} Invalid phone number.")
        else:
            print(f"{MENU_COLOR} Number:       {Fore.WHITE}{number}")
            print(f"{MENU_COLOR} Country:      {Fore.WHITE}{geocoder.description_for_number(parsed, 'en')}")
            print(f"{MENU_COLOR} Carrier:      {Fore.WHITE}{carrier.name_for_number(parsed, 'en')}")
            print(f"{MENU_COLOR} Timezone(s):  {Fore.WHITE}{', '.join(timezone.time_zones_for_number(parsed))}")
            print(f"{MENU_COLOR} Possible:     {Fore.WHITE}{phonenumbers.is_possible_number(parsed)}")
            print(f"{MENU_COLOR} Valid:        {Fore.WHITE}{phonenumbers.is_valid_number(parsed)}")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Phone Info Lookup UI
def phone_info_lookup_screen():
    clear()
    print(MENU_COLOR + r"""
  _____  _                        _____        __        _                 _                
 |  __ \| |                      |_   _|      / _|      | |               | |               
 | |__) | |__   ___  _ __   ___    | |  _ __ | |_ ___   | |     ___   ___ | | ___   _ _ __  
 |  ___/| '_ \ / _ \| '_ \ / _ \   | | | '_ \|  _/ _ \  | |    / _ \ / _ \| |/ / | | | '_ \ 
 | |    | | | | (_) | | | |  __/  _| |_| | | | || (_) | | |___| (_) | (_) |   <| |_| | |_) |
 |_|    |_| |_|\___/|_| |_|\___| |_____|_| |_|_| \___/  |______\___/ \___/|_|\_\\__,_| .__/ 
                                                                                     | |    
                                                                                     |_|    
    """)
    print(Fore.WHITE + """ Phone Info Lookup uses the phonenumbers library to retrieve general information
 about phone numbers, including the country, carrier, and timezone.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Phone Info Lookup")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_phone_info_lookup()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        phone_info_lookup_screen()

# Reverse DNS Lookup Logic
def run_reverse_dns():
    clear()
    ip_address = input(f"{Fore.WHITE} Enter IP address to reverse lookup: {Fore.GREEN}")
    print(f"{MENU_COLOR} Performing reverse DNS lookup on {ip_address}...\n")
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        print(f"{MENU_COLOR} Hostname: {Fore.WHITE}{host}")
    except socket.herror:
        print(f"{MENU_COLOR} No PTR record found or reverse DNS lookup failed.")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Reverse DNS Lookup UI
def reverse_dns_screen():
    clear()
    print(MENU_COLOR + r"""
  _____                                _____  _   _  _____   _                 _                
 |  __ \                              |  __ \| \ | |/ ____| | |               | |               
 | |__) |_____   _____ _ __ ___  ___  | |  | |  \| | (___   | |     ___   ___ | | ___   _ _ __  
 |  _  // _ \ \ / / _ \ '__/ __|/ _ \ | |  | | . ` |\___ \  | |    / _ \ / _ \| |/ / | | | '_ \ 
 | | \ \  __/\ V /  __/ |  \__ \  __/ | |__| | |\  |____) | | |___| (_) | (_) |   <| |_| | |_) |
 |_|  \_\___| \_/ \___|_|  |___/\___| |_____/|_| \_|_____/  |______\___/ \___/|_|\_\\__,_| .__/ 
                                                                                         | |    
                                                                                         |_|    
    """)
    print(Fore.WHITE + """ Reverse DNS Lookup tries to resolve an IP address back into a hostname.
 It uses the PTR records associated with the IP address (if available).\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Reverse DNS Lookup")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_reverse_dns()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        reverse_dns_screen()

# User Agent Parser Logic
def run_user_agent_parser():
    clear()
    ua_string = input(f"{Fore.WHITE} Enter a User-Agent string to parse: {Fore.GREEN}")
    print(f"{MENU_COLOR} Parsing User-Agent...\n")
    try:
        from user_agents import parse
    except ImportError:
        os.system(f"{sys.executable} -m pip install pyyaml ua-parser user-agents")
        from user_agents import parse

    try:
        ua = parse(ua_string)
        print(f"{MENU_COLOR} Device Type:  {Fore.WHITE}{'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'PC' if ua.is_pc else 'Other'}")
        print(f"{MENU_COLOR} OS:           {Fore.WHITE}{ua.os.family} {ua.os.version_string}")
        print(f"{MENU_COLOR} Browser:      {Fore.WHITE}{ua.browser.family} {ua.browser.version_string}")
        print(f"{MENU_COLOR} Is Bot:       {Fore.WHITE}{ua.is_bot}")
        print(f"{MENU_COLOR} Touch Capable:{Fore.WHITE}{ua.is_touch_capable}")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# User Agent Parser UI
def user_agent_parser_screen():
    clear()
    print(MENU_COLOR + r"""
  _    _                                             _     _____                         
 | |  | |                      /\                   | |   |  __ \                        
 | |  | |___  ___ _ __ ______ /  \   __ _  ___ _ __ | |_  | |__) |_ _ _ __ ___  ___ _ __ 
 | |  | / __|/ _ \ '__|______/ /\ \ / _` |/ _ \ '_ \| __| |  ___/ _` | '__/ __|/ _ \ '__|
 | |__| \__ \  __/ |        / ____ \ (_| |  __/ | | | |_  | |  | (_| | |  \__ \  __/ |   
  \____/|___/\___|_|       /_/    \_\__, |\___|_| |_|\__| |_|   \__,_|_|  |___/\___|_|   
                                     __/ |                                               
                                    |___/                                                
    """)
    print(Fore.WHITE + """ This tool parses a User-Agent string to identify the browser,
 operating system, device type, and other properties.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run User-Agent Parser")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")
    
    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_user_agent_parser()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        user_agent_parser_screen()

# Metadata Extractor Logic
from PIL import Image
from PIL.ExifTags import TAGS

def run_metadata_extractor():
    clear()
    image_path = input(rf"{Fore.WHITE} Enter the path to the image file: {Fore.GREEN}")
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()

        if exif_data is not None:
            print(f"\n{MENU_COLOR} Extracted Metadata:\n")
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                print(f"{Fore.WHITE} {tag}: {Fore.GREEN}{value}")
        else:
            print(f"\n{MENU_COLOR} No metadata found in this image.")

    except FileNotFoundError:
        print(f"\n{MENU_COLOR} File not found. Please check the path.")
    except Exception as e:
        print(f"\n{MENU_COLOR} Error: {e}")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Metadata Extractor UI
def metadata_extractor_screen():
    clear()
    print(MENU_COLOR + r"""
  __  __      _            _       _          ______      _                  _             
 |  \/  |    | |          | |     | |        |  ____|    | |                | |            
 | \  / | ___| |_ __ _  __| | __ _| |_ __ _  | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 | |\/| |/ _ \ __/ _` |/ _` |/ _` | __/ _` | |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
 | |  | |  __/ || (_| | (_| | (_| | || (_| | | |____ >  <| |_| | | (_| | (__| || (_) | |   
 |_|  |_|\___|\__\__,_|\__,_|\__,_|\__\__,_| |______/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
    """)
    print(Fore.WHITE + """ A metadata extractor reads hidden data stored within image files, such as
 device info, GPS coordinates, timestamps, and camera settings.

 Useful in OSINT investigations, but always analyze files you are authorized to access.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Metadata Extractor")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_metadata_extractor()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        metadata_extractor_screen()

import requests

def run_subdomain_finder():
    clear()
    domain = input(f"{Fore.WHITE} Enter domain to scan for subdomains (e.g., example.com): {Fore.GREEN}")
    subdomains = [
        "www", "mail", "ftp", "test", "dev", "api", "blog", "staging", "shop", "admin"
    ]

    found_subdomains = []

    print(f"\n{MENU_COLOR} Scanning for subdomains on {domain}...\n")
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code < 400:
                print(f"{Fore.WHITE} Found: {Fore.GREEN}{url}")
                found_subdomains.append(url)
        except requests.ConnectionError:
            pass
        except requests.Timeout:
            pass

    if not found_subdomains:
        print(f"\n{MENU_COLOR} No subdomains found or reachable.")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

def subdomain_finder_screen():
    clear()
    print(MENU_COLOR + r"""
   _____       _         _                       _         ______ _           _           
  / ____|     | |       | |                     (_)       |  ____(_)         | |          
 | (___  _   _| |__   __| | ___  _ __ ___   __ _ _ _ __   | |__   _ _ __   __| | ___ _ __ 
  \___ \| | | | '_ \ / _` |/ _ \| '_ ` _ \ / _` | | '_ \  |  __| | | '_ \ / _` |/ _ \ '__|
  ____) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | | | |    | | | | | (_| |  __/ |   
 |_____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_| |_|    |_|_| |_|\__,_|\___|_|   
    """)
    print(Fore.WHITE + """ A Subdomain Finder tries to discover subdomains related to a domain.
 Useful for footprinting and reconnaissance during ethical hacking.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Subdomain Finder")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_subdomain_finder()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        subdomain_finder_screen()

def run_payload_generator():
    clear()
    print(f"{MENU_COLOR} Select payload type:\n")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} XSS Payloads")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} SQL Injection Payloads")
    print(f"{MENU_COLOR} [3]{Fore.WHITE} Command Injection Payloads")
    print(f"{MENU_COLOR} [4]{Fore.WHITE} Local File Inclusion (LFI) Payloads")
    print(f"{MENU_COLOR} [5]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    
    if choice == "1":
        clear()
        print(f"{MENU_COLOR} XSS Payloads:\n")
        xss_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ]
        for payload in xss_payloads:
            print(f"{Fore.GREEN} {payload}")
    elif choice == "2":
        clear()
        print(f"{MENU_COLOR} SQL Injection Payloads:\n")
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "' OR 1=1--"
        ]
        for payload in sql_payloads:
            print(f"{Fore.GREEN} {payload}")
    elif choice == "3":
        clear()
        print(f"{MENU_COLOR} Command Injection Payloads:\n")
        cmd_injection_payloads = [
            "test; ls -la",
            "test && whoami",
            "test | cat /etc/passwd",
            "test || id"
        ]
        for payload in cmd_injection_payloads:
            print(f"{Fore.GREEN} {payload}")
    elif choice == "4":
        clear()
        print(f"{MENU_COLOR} Local File Inclusion (LFI) Payloads:\n")
        lfi_payloads = [
            "../../etc/passwd",
            "../../../../../../etc/shadow",
            "/etc/passwd%00",
            "..%2f..%2f..%2fetc%2fpasswd"
        ]
        for payload in lfi_payloads:
            print(f"{Fore.GREEN} {payload}")
    elif choice == "5":
        main_menu()
    else:
        print(f"{MENU_COLOR} Invalid choice. Returning...")
        time.sleep(2)
        run_payload_generator()

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

def payload_generator_screen():
    clear()
    print(MENU_COLOR + r"""
  _____            _                 _    _____                           _             
 |  __ \          | |               | |  / ____|                         | |            
 | |__) |_ _ _   _| | ___   __ _  __| | | |  __  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
 |  ___/ _` | | | | |/ _ \ / _` |/ _` | | | |_ |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
 | |  | (_| | |_| | | (_) | (_| | (_| | | |__| |  __/ | | |  __/ | | (_| | || (_) | |   
 |_|   \__,_|\__, |_|\___/ \__,_|\__,_|  \_____|\___|_| |_|\___|_|  \__,_|\__\___/|_|   
              __/ |                                                                     
             |___/                                                                      
    """)
    print(Fore.WHITE + """ A payload generator creates common payloads for testing security vulnerabilities
 like XSS, SQLi, Command Injection, and LFI.

 These payloads can be used during penetration testing and ethical hacking.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Payload Generator")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_payload_generator()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        payload_generator_screen()

import hashlib

def run_hash_identifier():
    clear()
    hash_input = input(f"{Fore.WHITE} Enter the hash to identify: {Fore.GREEN}").strip()
    
    hash_lengths = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512"
    }

    print(f"\n{MENU_COLOR} Analyzing hash...\n")
    possible_hash = hash_lengths.get(len(hash_input))

    if possible_hash:
        print(f"{Fore.WHITE} Possible hash type: {Fore.GREEN}{possible_hash}")
    else:
        print(f"{MENU_COLOR} Unable to determine hash type based on length.")
    
    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

def hash_identifier_screen():
    clear()
    print(MENU_COLOR + r"""
  _    _           _       _____    _            _   _  __ _           
 | |  | |         | |     |_   _|  | |          | | (_)/ _(_)          
 | |__| | __ _ ___| |__     | |  __| | ___ _ __ | |_ _| |_ _  ___ _ __ 
 |  __  |/ _` / __| '_ \    | | / _` |/ _ \ '_ \| __| |  _| |/ _ \ '__|
 | |  | | (_| \__ \ | | |  _| || (_| |  __/ | | | |_| | | | |  __/ |   
 |_|  |_|\__,_|___/_| |_| |_____\__,_|\___|_| |_|\__|_|_| |_|\___|_|   
    """)
    print(Fore.WHITE + """ Hash Identifier tries to detect the hashing algorithm
 used based on the hash length (e.g., MD5, SHA-1, SHA-256).

 Useful for forensic investigations or decoding attempts.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Hash Identifier")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_hash_identifier()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        hash_identifier_screen()

import requests

def run_dir_bruteforcer():
    clear()
    url = input(f"{Fore.WHITE} Enter the base URL (e.g., http://example.com/): {Fore.GREEN}")
    wordlist = [
        "admin", "login", "dashboard", "config", "uploads", "images", 
        "js", "css", "backup", "old", "private", "test"
    ]

    if not url.endswith('/'):
        url += '/'

    print(f"\n{MENU_COLOR} Scanning {url} for directories/files...\n")

    for word in wordlist:
        test_url = url + word
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"{Fore.GREEN} Found: {Fore.WHITE}{test_url}")
            elif response.status_code == 403:
                print(f"{Fore.YELLOW} Forbidden (but exists!): {Fore.WHITE}{test_url}")
        except requests.RequestException:
            print(f"{MENU_COLOR} Error connecting to {test_url}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

def dir_bruteforcer_screen():
    clear()
    print(MENU_COLOR + r"""
  _____  _               _                       ________ _ _        ____             _        __                        
 |  __ \(_)             | |                     / /  ____(_) |      |  _ \           | |      / _|                       
 | |  | |_ _ __ ___  ___| |_ ___  _ __ _   _   / /| |__   _| | ___  | |_) |_ __ _   _| |_ ___| |_ ___  _ __ ___ ___ _ __ 
 | |  | | | '__/ _ \/ __| __/ _ \| '__| | | | / / |  __| | | |/ _ \ |  _ <| '__| | | | __/ _ \  _/ _ \| '__/ __/ _ \ '__|
 | |__| | | | |  __/ (__| || (_) | |  | |_| |/ /  | |    | | |  __/ | |_) | |  | |_| | ||  __/ || (_) | | | (_|  __/ |   
 |_____/|_|_|  \___|\___|\__\___/|_|   \__, /_/   |_|    |_|_|\___| |____/|_|   \__,_|\__\___|_| \___/|_|  \___\___|_|   
                                        __/ |                                                                            
                                       |___/                                                                             
    """)
    print(Fore.WHITE + """ Directory/File Bruteforcer tries to discover hidden
 admin panels, folders, or important files by brute-forcing URLs.

 Useful for penetration testing or security assessments.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Directory/File Bruteforcer")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_dir_bruteforcer()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        dir_bruteforcer_screen()

# Ping Tool Logic
def run_ping_tool():
    import subprocess
    clear()
    target = input(f"{Fore.WHITE} Enter IP address or domain to ping (e.g., example.com): {Fore.GREEN}")
    print(f"{MENU_COLOR} Pinging {target}...\n")

    try:
        if os.name == 'nt':
            # Windows
            result = subprocess.check_output(["ping", "-n", "4", target], text=True)
        else:
            # Linux / Mac
            result = subprocess.check_output(["ping", "-c", "4", target], text=True)

        print(Fore.WHITE + result)
    except subprocess.CalledProcessError:
        print(f"{MENU_COLOR} Ping failed. Host may be unreachable.")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Ping Tool UI
def ping_tool_screen():
    clear()
    print(MENU_COLOR + r"""
  _____ _               _______          _ 
 |  __ (_)             |__   __|        | |
 | |__) | _ __   __ _     | | ___   ___ | |
 |  ___/ | '_ \ / _` |    | |/ _ \ / _ \| |
 | |   | | | | | (_| |    | | (_) | (_) | |
 |_|   |_|_| |_|\__, |    |_|\___/ \___/|_|
                 __/ |                     
                |___/                      
    """)
    print(Fore.WHITE + """ The Ping Tool checks the reachability of a host by sending ICMP Echo Requests.
 It helps diagnose network connectivity issues.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Ping Tool")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_ping_tool()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        ping_tool_screen()

# SSL/TLS Scanner Logic
def run_ssl_tls_scanner():
    import ssl
    import socket
    clear()
    domain = input(f"{Fore.WHITE} Enter domain to scan (e.g., example.com): {Fore.GREEN}").strip()
    print(f"{MENU_COLOR} Scanning SSL/TLS information for {domain}...\n")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()

        print(f"{MENU_COLOR} Subject: {Fore.WHITE}{cert.get('subject')}")
        print(f"{MENU_COLOR} Issuer: {Fore.WHITE}{cert.get('issuer')}")
        print(f"{MENU_COLOR} Valid From: {Fore.WHITE}{cert.get('notBefore')}")
        print(f"{MENU_COLOR} Valid Until: {Fore.WHITE}{cert.get('notAfter')}")
        print(f"{MENU_COLOR} Serial Number: {Fore.WHITE}{cert.get('serialNumber')}")
        print(f"{MENU_COLOR} Version: {Fore.WHITE}{cert.get('version')}")
    except ssl.SSLError as e:
        print(f"{MENU_COLOR} SSL Error: {e}")
    except socket.gaierror:
        print(f"{MENU_COLOR} Error: Could not resolve domain.")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# SSL/TLS Scanner UI
def ssl_tls_scanner_screen():
    clear()
    print(MENU_COLOR + r"""
   _____ _____ _          _________ _       _____    _____                                 
  / ____/ ____| |        / /__   __| |     / ____|  / ____|                                
 | (___| (___ | |       / /   | |  | |    | (___   | (___   ___ __ _ _ __  _ __   ___ _ __ 
  \___ \\___ \| |      / /    | |  | |     \___ \   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ____) |___) | |____ / /     | |  | |____ ____) |  ____) | (_| (_| | | | | | | |  __/ |   
 |_____/_____/|______/_/      |_|  |______|_____/  |_____/ \___\__,_|_| |_|_| |_|\___|_|   
    """)
    print(Fore.WHITE + """ The SSL/TLS Scanner retrieves certificate information
 from a domain including issuer, validity period, and subject details.\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run SSL/TLS Scanner")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_ssl_tls_scanner()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        ssl_tls_scanner_screen()

# Open Directory Finder Logic
def run_open_directory_finder():
    clear()
    target = input(f"{Fore.WHITE} Enter target URL (e.g., http://example.com/): {Fore.GREEN}").strip()

    if not target.endswith('/'):
        target += '/'

    common_dirs = ["admin", "backup", "uploads", "files", "images", "downloads", "private", "logs"]

    print(f"\n{MENU_COLOR} Scanning common directories...\n")

    try:
        import requests
        for dir in common_dirs:
            url = target + dir + '/'
            try:
                response = requests.get(url, timeout=5)
                if "Index of" in response.text and response.status_code == 200:
                    print(f"{Fore.GREEN} [+] Open directory found: {url}")
                else:
                    print(f"{Fore.WHITE} [-] {url}")
            except requests.exceptions.RequestException:
                print(f"{MENU_COLOR} [!] Failed to reach: {url}")
    except Exception as e:
        print(f"{MENU_COLOR} Error: {e}")

    input(f"\n{MENU_COLOR} Press Enter to return to menu...")
    main_menu()

# Open Directory Finder UI
def open_directory_finder_screen():
    clear()
    print(MENU_COLOR + r"""
   ____                     _____  _               _                     ______ _           _           
  / __ \                   |  __ \(_)             | |                   |  ____(_)         | |          
 | |  | |_ __   ___ _ __   | |  | |_ _ __ ___  ___| |_ ___  _ __ _   _  | |__   _ _ __   __| | ___ _ __ 
 | |  | | '_ \ / _ \ '_ \  | |  | | | '__/ _ \/ __| __/ _ \| '__| | | | |  __| | | '_ \ / _` |/ _ \ '__|
 | |__| | |_) |  __/ | | | | |__| | | | |  __/ (__| || (_) | |  | |_| | | |    | | | | | (_| |  __/ |   
  \____/| .__/ \___|_| |_| |_____/|_|_|  \___|\___|\__\___/|_|   \__, | |_|    |_|_| |_|\__,_|\___|_|   
        | |                                                       __/ |                                 
        |_|                                                      |___/                                  
    """)
    print(Fore.WHITE + """ Open Directory Finder checks for publicly accessible open directories
 on the target website. Open directories often expose sensitive files!\n""")
    print(f"{MENU_COLOR} [1]{Fore.WHITE} Run Open Directory Finder")
    print(f"{MENU_COLOR} [2]{Fore.WHITE} Back to Menu\n")

    choice = input(MENU_COLOR + " [?]> " + Fore.WHITE)
    if choice == "1":
        run_open_directory_finder()
    elif choice == "2":
        main_menu()
    else:
        print(MENU_COLOR + " Invalid choice. Returning...")
        time.sleep(2)
        open_directory_finder_screen()


from colorama import Fore, Style
import os
import sys
import time

# Default menu color
MENU_COLOR = Fore.RED

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def set_menu_color():
    global MENU_COLOR
    clear()
    print(" Choose a color theme:\n")
    print(f" [1] {Fore.RED}Red{Fore.RESET}")
    print(f" [2] {Fore.GREEN}Green{Fore.RESET}")
    print(f" [3] {Fore.BLUE}Blue{Fore.RESET}")
    print(f" [4] {Fore.YELLOW}Yellow{Fore.RESET}")
    print(f" [5] {Fore.MAGENTA}Magenta{Fore.RESET}")
    print(f" [6] {Fore.CYAN}Cyan{Fore.RESET}")

    choice = input("\n Your choice: ").strip()
    color_map = {
        "1": Fore.RED,
        "2": Fore.GREEN,
        "3": Fore.BLUE,
        "4": Fore.YELLOW,
        "5": Fore.MAGENTA,
        "6": Fore.CYAN
    }

    MENU_COLOR = color_map.get(choice, MENU_COLOR)

def main_menu():
    clear()
    print('')
    print(rf'{MENU_COLOR}    __  __     ______     ______     __  __     ______     __  __    {Fore.RESET}')
    print(rf'{MENU_COLOR}   /\ \_\ \   /\  __ \   /\  ___\   /\ \/ /    /\___  \   /\ \_\ \   {Fore.RESET}')
    print(rf'{MENU_COLOR}   \ \  __ \  \ \  __ \  \ \ \____  \ \  _"-.  \/_/  /__  \ \____ \  {Fore.RESET}') 
    print(rf'{MENU_COLOR}    \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\   /\_____\  \/\_____\ {Fore.RESET}')
    print(rf'{MENU_COLOR}     \/_/\/_/   \/_/\/_/   \/_____/   \/_/\/_/   \/_____/   \/_____/ {Fore.RESET}')
    print('') 
    print(rf'{MENU_COLOR}                              Version{Fore.WHITE} 2.0.0              {Fore.RESET}')
    print(f"{Fore.LIGHTWHITE_EX}                You are fully responsible for your actions.")
    print(f"{Fore.LIGHTBLACK_EX}                © 2025 Cr3zy (https://github.com/Cr3zy-dev){Fore.RESET}")
    print(rf"                  {MENU_COLOR}[{Fore.WHITE}::{MENU_COLOR}] Select A Number From The Menu {MENU_COLOR}[{Fore.WHITE}::{MENU_COLOR}]")
    print('')

    print(f"{MENU_COLOR} [01]{Fore.WHITE} Port Scanner            {MENU_COLOR}[11]{Fore.WHITE} Metadata Extractor    {MENU_COLOR}[21]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [02]{Fore.WHITE} IP Tracker              {MENU_COLOR}[12]{Fore.WHITE} Subdomain Finder      {MENU_COLOR}[22]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [03]{Fore.WHITE} Whois Lookup            {MENU_COLOR}[13]{Fore.WHITE} Payload Generator     {MENU_COLOR}[23]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [04]{Fore.WHITE} DNS Resolver            {MENU_COLOR}[14]{Fore.WHITE} Hash Identifier       {MENU_COLOR}[24]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [05]{Fore.WHITE} Email Scraper           {MENU_COLOR}[15]{Fore.WHITE} Dir/File Bruteforcer  {MENU_COLOR}[25]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [06]{Fore.WHITE} Traceroute              {MENU_COLOR}[16]{Fore.WHITE} Ping Tool             {MENU_COLOR}[26]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [07]{Fore.WHITE} Header Analyzer         {MENU_COLOR}[17]{Fore.WHITE} SSL/TLS Scanner       {MENU_COLOR}[27]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [08]{Fore.WHITE} Phone Info Lookup       {MENU_COLOR}[18]{Fore.WHITE} Open Directory Finder {MENU_COLOR}[28]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [09]{Fore.WHITE} Reverse DNS Lookup      {MENU_COLOR}[19]{Fore.WHITE} SOON                  {MENU_COLOR}[29]{Fore.WHITE} SOON")
    print(f"{MENU_COLOR} [10]{Fore.WHITE} User-Agent Parser       {MENU_COLOR}[20]{Fore.WHITE} SOON                  {MENU_COLOR}[30]{Fore.WHITE} SOON")  
    print('')
    print(f"{MENU_COLOR} [98]{Fore.WHITE} Color themes")
    print(f"{MENU_COLOR} [99]{Fore.WHITE} Exit")
    print('')

    choice = input(MENU_COLOR + ' [?]> ' + Fore.WHITE).lstrip('0')

    if choice == "1":
        port_scanner_screen()
    elif choice == "2":
        ip_tracker_screen()
    elif choice == "3":
        whois_lookup_screen()
    elif choice == "4":
        dns_resolver_screen()
    elif choice == "5":
        email_scraper_screen()
    elif choice == "6":
        traceroute_screen()
    elif choice == "7":
        header_analyzer_screen()
    elif choice == "8":
        phone_info_lookup_screen()
    elif choice == "9":
        reverse_dns_screen()
    elif choice == "10":
        user_agent_parser_screen()
    elif choice == "11":
        metadata_extractor_screen()
    elif choice == "12":
        subdomain_finder_screen()
    elif choice == "13":
        payload_generator_screen()
    elif choice == "14":
        hash_identifier_screen()
    elif choice == "15":
        dir_bruteforcer_screen()
    elif choice == "16":
        ping_tool_screen()
    elif choice == "17":
        ssl_tls_scanner_screen()
    elif choice == "18":
        open_directory_finder_screen()
    elif choice == "98":
        set_menu_color()
        main_menu()
    elif choice == "99":
        print(Fore.GREEN + " Goodbye!" + Fore.RESET)
        sys.exit()
    else:
        print(MENU_COLOR + " Invalid choice. Returning to main menu...")
        time.sleep(2)
        main_menu()

# Start
clear()
main_menu()
