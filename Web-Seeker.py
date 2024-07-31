import requests
from urllib.parse import urlparse
import re
import pandas as pd
import socket
import argparse
import time
import os
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from pyfiglet import Figlet
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

# List of common CMS identifiers
CMS_IDENTIFIERS = {
    'WordPress': {
        'headers': ['x-powered-by', 'x-pingback'],
        'patterns': [r'wp-content', r'wp-includes'],
        'files': ['wp-login.php', 'wp-admin/']
    },
    'Joomla': {
        'headers': ['x-joomla-cache'],
        'patterns': [r'joomla'],
        'files': ['administrator/', 'templates/']
    },
    'Drupal': {
        'headers': ['x-drupal-cache'],
        'patterns': [r'drupal'],
        'files': ['sites/all/themes/', 'sites/all/modules/']
    },
    'Magento': {
        'headers': ['x-magento-cache-debug'],
        'patterns': [r'mage'],
        'files': ['admin/', 'skin/frontend/']
    },
    'Shopify': {
        'headers': ['x-shopify-stage'],
        'patterns': [r'shopify'],
        'files': ['collections/all', 'products']
    },
    'Wix': {
        'headers': [],
        'patterns': [r'wix'],
        'files': ['wix.com']
    }
}

# Function to check for specific headers
def check_headers(headers):
    for cms, details in CMS_IDENTIFIERS.items():
        for header in details['headers']:
            if header in headers:
                return cms
    return None

# Function to check for specific patterns in the content
def check_patterns(content):
    for cms, details in CMS_IDENTIFIERS.items():
        for pattern in details['patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                return cms
    return None

# Function to check for specific files
def check_files(url, timeout):
    for cms, details in CMS_IDENTIFIERS.items():
        for file in details['files']:
            try:
                full_url = url.rstrip('/') + '/' + file
                response = requests.get(full_url, timeout=timeout, verify=False)
                if response.status_code == 200:
                    return cms
            except requests.RequestException:
                continue
    return None

# Main function to identify the CMS
def identify_cms(url, timeout):
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        headers = response.headers
        content = response.text

        # Check headers
        cms = check_headers(headers)
        if cms:
            return cms

        # Check content patterns
        cms = check_patterns(content)
        if cms:
            return cms

        # Check for specific files
        cms = check_files(url, timeout)
        if cms:
            return cms

        return "Unknown CMS"
    except requests.RequestException as e:
        print(colored(f"Error accessing {url}: {e}", "red"))
        return "Error"

# Setup Selenium WebDriver for Firefox
def setup_driver(geckodriver_path):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Firefox(service=Service(geckodriver_path), options=options)
    return driver

# Fetch dynamic files using Selenium and Firefox
def fetch_dynamic_files(url, geckodriver_path):
    driver = setup_driver(geckodriver_path)
    driver.get(url)
    time.sleep(3)  # Wait for the page to fully load
    
    # Get all network requests
    entries = driver.execute_script("return window.performance.getEntries();")
    
    found_files = set()
    base_domain = urlparse(url).netloc
    for entry in entries:
        if 'name' in entry:
            file_url = entry['name']
            parsed_url = urlparse(file_url)
            if parsed_url.netloc == base_domain:
                found_files.add(file_url)

    driver.quit()
    return list(found_files)

# Function to perform fuzzing for additional files and directories
def perform_request(url, timeout):
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        if response.status_code == 200:
            return url
    except requests.RequestException:
        pass
    return None

def fuzz_for_files(base_url, cms, timeout):
    found_files = []
    extensions = ['.txt', '.html', '.js', '.css']
    fuzzing_dir = os.path.join(os.path.dirname(__file__), 'fuzzing')

    # Determine the appropriate wordlist based on the CMS
    if cms == 'WordPress':
        wordlist_file = os.path.join(fuzzing_dir, 'wordpress-fuzz.txt')
    elif cms == 'Joomla':
        wordlist_file = os.path.join(fuzzing_dir, 'joomla-fuzz.txt')
    else:
        wordlist_file = os.path.join(fuzzing_dir, 'wordlist.txt')

    print(colored("Performing fuzzing...", "cyan"))
    try:
        with open(wordlist_file, 'r') as file:
            words = file.read().splitlines()

        # Construct URLs to check based on CMS type
        if cms in ['WordPress', 'Joomla']:
            # Use words as they are without adding extensions
            urls_to_check = [f"{base_url.rstrip('/')}/{word}" for word in words]
        else:
            # Add extensions to words for general wordlist
            urls_to_check = [f"{base_url.rstrip('/')}/{word}{ext}" for word in words for ext in extensions]

        # Perform requests in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda url: perform_request(url, timeout), urls_to_check))

        found_files = [result for result in results if result]

    except FileNotFoundError:
        print(colored(f"Wordlist file not found: {wordlist_file}", "red"))
    
    return found_files

# Search for sensitive information in the files
def search_sensitive_info(content, base_ip):
    sensitive_info = []

    # Patterns for usernames, passwords, emails, IP addresses, and hashes
    patterns = {
        "username": r'\busern?am?e?\b\s*[:=]\s*["\']?(\w+)["\']?|my\s+usern?am?e?\s+is\s+(\w+)|my\s+usrnm\s+is\s+(\w+)|my\s+usr\s+(\w+)|\buser\b\s*[:=]\s*["\']?(\w+)["\']?',
        "password": r'\bpass(word)?\b\s*[:=]\s*["\']?(\w+)["\']?|my\s+password\s+is\s+(\w+)|my\s+pass\s+is\s+(\w+)|my\s+pass\s+(\w+)|to\s+enter\s+put\s+this\s+(\w+)',
        "credentials": r'\b(credentials|creds)\b\s*[:=]\s*["\']?(\w+)["\']?|my\s+credentials\s+are\s+(\w+)',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "ip": r'\b(?<!\d\.)(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\.\d)\b',
        "hash": r'(?<!\w)([a-f0-9]{32}|[A-F0-9]{32})\b(?!\.(mp3|mp4|jpg|jpeg|png|gif))|'  # MD5 excluding media files
                r'(?<!\w)([a-f0-9]{40}|[A-F0]{40})\b(?!\.(mp3|mp4|jpg|jpeg|png|gif))|'  # SHA-1 excluding media files
                r'(?<!\w)([a-f0-9]{64}|[A-F0-9]{64})\b(?!\.(mp3|mp4|jpg|jpeg|png|gif))|'  # SHA-256 excluding media files
                r'(?<!\w)([a-f0-9]{128}|[A-F0-9]{128})\b(?!\.(mp3|mp4|jpg|jpeg|png|gif))'  # SHA-512 excluding media files
    }

    for info_type, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            for match in matches:
                if isinstance(match, tuple):
                    match_value = next(filter(None, match))
                else:
                    match_value = match
                # Exclude the base IP of the website
                if info_type == "ip" and match_value == base_ip:
                    continue
                sensitive_info.append((info_type, match_value))

    return sensitive_info

# Function to detect website language
def detect_language(content):
    # Basic detection based on common language indicators
    if "<html lang=\"en\"" in content.lower():
        return "English"
    elif "<html lang=\"he\"" in content.lower():
        return "Hebrew"
    elif "<html lang=\"es\"" in content.lower():
        return "Spanish"
    # Add more languages as needed
    return "Unknown"

# Generate HTML report
def generate_html_report(cms, sensitive_data, found_files, errors, output_file, url, ip_address, language, certificate_info):
    # Define color mapping for each type
    type_color_mapping = {
        'email': '#FFD700',        
        'credentials': '#FF4500',  
        'hash': '#A9A9A9',        
        'ip': '#32CD32',           
        'username': '#FFA500',     
        'password': '#DC143C'      
    }

    
    df_sensitive = pd.DataFrame(sensitive_data, columns=['Type', 'Value', 'File URL'])
    df_files = pd.DataFrame(found_files, columns=['Found Files'])
    df_errors = pd.DataFrame(errors, columns=['Error Message'])

    
    output_dir = os.path.join(os.path.dirname(__file__), 'Report')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    
    css_path = "report.css"

    
    html_content = f"""
    <html>
    <head>
        <title>Page-Seeker Report</title>
        <link rel="stylesheet" type="text/css" href="{css_path}">
    </head>
    <body>
        <div class="container">
            <h1>Page-Seeker</h1>
            <p class="copyright">© by Shaked Wiessman</p>
            <div>
                <h2>Website Information</h2>
                <table class="info-table">
                    <tr><th>URL</th><td>{url}</td></tr>
                    <tr><th>CMS</th><td>{cms}</td></tr>
                    <tr><th>Language</th><td>{language}</td></tr>
                    <tr><th>IP Address</th><td>{ip_address}</td></tr>
                    <tr><th>Certificate</th><td>{certificate_info}</td></tr>
                </table>
            </div>
            <h2>Found Files</h2>
            <div class="dataframe">
                {df_files.to_html(index=False, escape=False)}
            </div>

            <h2>Sensitive Information</h2>
    """

    
    for info_type, color in type_color_mapping.items():
        relevant_data = df_sensitive[df_sensitive['Type'].str.lower() == info_type]
        if not relevant_data.empty:
            html_content += f"""
            <button class="collapsible" style="background-color: {color};">{info_type.capitalize()}</button>
            <div class="content">
                <table>
                    <tr><th>Value</th><th>File URL</th></tr>
            """
            for _, row in relevant_data.iterrows():
                html_content += f"<tr><td>{row['Value']}</td><td>{row['File URL']}</td></tr>"
            html_content += "</table></div>"

    html_content += f"""
            <h2>Errors</h2>
            {df_errors.to_html(index=False, escape=False) if not df_errors.empty else '<p>No errors occurred.</p>'}
        </div>
        <div class="footer">
            <p>Generated by Page-Seeker</p>
        </div>
        <script>
        var coll = document.getElementsByClassName("collapsible");
        var i;

        for (i = 0; i < coll.length; i++) {{
            coll[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.display === "block") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "block";
                }}
            }});
        }}
        </script>
    </body>
    </html>
    """

    
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, 'w') as file:
        file.write(html_content)


def display_banner():
    f = Figlet(font='slant')
    print(colored(f.renderText('Page-Seeker'), 'cyan', attrs=['bold']))
    print(colored('by Shaked Wiessman', 'green'))


if __name__ == "__main__":
    # Display the banner
    display_banner()

    parser = argparse.ArgumentParser(description="Scan a website for files and sensitive information.")
    parser.add_argument('-url', type=str, required=True, help='URL of the website to check')
    parser.add_argument('-outfile', type=str, required=True, help='Output HTML file name (without path)')
    parser.add_argument('-geckodriver', type=str, required=True, help='Path to the GeckoDriver executable')
    parser.add_argument('-timeout', type=int, default=10, help='Timeout for HTTP requests (default is 10 seconds)')
    args = parser.parse_args()

    website_url = args.url
    output_file = args.outfile
    geckodriver_path = args.geckodriver
    timeout = args.timeout

    try:
        
        base_ip = socket.gethostbyname(urlparse(website_url).hostname)

        
        cms = identify_cms(website_url, timeout)
        print(colored(f"The website is using: {cms}", "blue"))

        
        print(colored("Scanning for files...", "yellow"))
        found_files = fetch_dynamic_files(website_url, geckodriver_path)
        print(colored(f"Found {len(found_files)} files via dynamic scanning.", "green"))

        
        print(colored("Performing fuzzing for additional files...", "yellow"))
        fuzzed_files = fuzz_for_files(website_url, cms, timeout)
        print(colored(f"Found {len(fuzzed_files)} files via fuzzing.", "green"))

        
        all_found_files = list(set(found_files + fuzzed_files))

        sensitive_data = []
        errors = []

        
        try:
            main_page_response = requests.get(website_url, timeout=timeout, verify=False)
            main_page_content = main_page_response.text
            language = detect_language(main_page_content)
        except requests.RequestException as e:
            print(colored(f"Error accessing main page: {e}", "red"))
            language = "Unknown"

        
        certificate_info = "Not implemented"

        for file_url in all_found_files:
            try:
                response = requests.get(file_url, timeout=timeout, verify=False)
                content = response.text
                sensitive_info = search_sensitive_info(content, base_ip)
                for info_type, value in sensitive_info:
                    sensitive_data.append((info_type, value, file_url))
            except requests.RequestException as e:
                errors.append(str(e))
                print(colored(f"Error accessing {file_url}: {e}", "red"))

    except requests.RequestException as e:
        print(colored(f"Could not access the website: {e}", "red"))
        errors.append(f"Could not access the website: {e}")
        cms = "Unknown"
        all_found_files = []
        sensitive_data = []
        language = "Unknown"
        certificate_info = "Not implemented"

    generate_html_report(cms, sensitive_data, all_found_files, errors, output_file, website_url, base_ip, language, certificate_info)
    print(colored(f"Report generated: {output_file}", "cyan"))

