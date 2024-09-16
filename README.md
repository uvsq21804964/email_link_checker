# email_link_checker

### Usage

You need to export/save all your mails to a .eml file and put it in the same directory as the script.

Then you can run the script with the following command:

```bash
pip install -r requirements.txt
python email_link_checker.py
```

### Some details

1. I tested my script using only Outlook client, so I can't guarantee that it will work with other clients.

### Process

1. Basically, the script will read all the .eml files in the directory and extract the links from the body of the email.
2. Then it will check if the domains of the links are valid or not according to VirusTotal.
