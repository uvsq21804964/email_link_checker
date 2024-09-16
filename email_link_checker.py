import email
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from pathlib import Path
import os

class bcolors:
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    DANGER = '\033[91m'
    ENDC = '\033[0m'

VIRUS_TOTAL_API_KEY = "464b7fe93085489a7777adf5a3d3d0f43c30e91c62430aa900fd5946a31561f0"
URL = "https://www.virustotal.com/api/v3/domains/"
TO_CHECK = ["malicious", "suspicious"]

def extract_links_from_email(email_content):
    soup = BeautifulSoup(email_content, "html.parser")
    links = [a.get('href') for a in soup.find_all('a', href=True)]
    return links

def is_dangerous_domain(domain):
    headers = {"accept": "application/json", "x-apikey": VIRUS_TOTAL_API_KEY}
    response = requests.get(URL + domain, headers=headers)
    json = response.json()
    stats = json["data"]["attributes"]["last_analysis_stats"]
    
    dangerous = False
    
    print(f"Analyse du domaine {domain} :")
    for key in stats.keys():
        if stats[key] > 0:
            print(f" * {key}: {stats[key]}")
            if key in TO_CHECK:
                dangerous = True
            
    return dangerous

def analyze_email(email_file_path, filename):
    print(bcolors.OKCYAN + f"Analyse de l'email :")
    print(filename + bcolors.ENDC, end="\n\n")
     
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
            dangerous = False
            links = extract_links_from_email(email_content)
            domains = [urlparse(link).netloc for link in links]
            for domain in domains:
                if is_dangerous_domain(domain):
                    print(bcolors.WARNING + f"Potentiel domaine dangereux détecté : {domain}\n"  + bcolors.ENDC)
                    dangerous = True
                else:
                    print(bcolors.OKGREEN + f"Domaine sûr détecté : {domain}\n" + bcolors.ENDC)
        else:
            print("L'email n'est pas au format HTML\n")
            return
    
    if dangerous:
        print(bcolors.DANGER + f"L'email '{filename}' contient des liens dangereux!" + bcolors.ENDC, end="\n"*3)
    else:
        print(bcolors.OKCYAN + f"L'email '{filename}' ne contient pas de liens dangereux." + bcolors.ENDC, end="\n"*3)
            

if __name__ == "__main__":
    # Retrieve the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Analyze all the .eml files in the script directory
    for filename in os.listdir(script_dir):
        file_path = os.path.join(script_dir, filename)
        if os.path.isfile(file_path) and filename.endswith(".eml"):
            analyze_email(file_path, filename)