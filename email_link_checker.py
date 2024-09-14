import chardet
import email
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from pathlib import Path
import os

# Blacklist of dangerous domains to check against when analyzing URLs in emails
DANGEROUS_DOMAINS = [
    "example.com", "malicious.com", "phishing.com"
]

def extract_links_from_email(email_content):
    soup = BeautifulSoup(email_content, "html.parser")
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    return links

def is_dangerous_url(url):
    # Check if the URL contains a dangerous domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if any(dangerous_domain in domain for dangerous_domain in DANGEROUS_DOMAINS):
        return True

    try:
        response = requests.get(url, timeout=5)
        # Mock the response status code to test the dangerous URL detection
        if response.status_code == 200:
            return False
        else:
            return True
    except requests.RequestException:
        return True

def analyze_email(email_file_path):
    with open(email_file_path, 'rb') as file:
        msg = email.message_from_binary_file(file)
        # Retrieve the email encoding
        encoding = msg.get_content_charset() or 'utf-8'

        try:
            email_content = msg.get_payload(decode=True).decode(encoding)
        except (UnicodeDecodeError, TypeError):
            # If the decoding fails, try to detect the encoding
            email_content = msg.get_payload(decode=True).decode('latin1', errors='ignore')

        # If the email is in HTML format, extract the links
        if 'html' in msg.get_content_type():
            links = extract_links_from_email(email_content)
            for link in links:
                if is_dangerous_url(link):
                    print(f"Potentiel site dangereux détecté : {link}")
                else:
                    print(f"Site sûr détecté : {link}")
        else:
            print("L'email n'est pas au format HTML")

if __name__ == "__main__":
    # Retrieve the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Analyze all the .eml files in the script directory
    for filename in os.listdir(script_dir):
        file_path = os.path.join(script_dir, filename)
        if os.path.isfile(file_path) and filename.endswith(".eml"):
            print(f"Analyse de l'email : {filename}")
            analyze_email(file_path)
            print(f"Fins de l'analyse de l'email : {filename}")