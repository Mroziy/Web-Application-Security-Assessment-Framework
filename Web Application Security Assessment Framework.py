import requests
from bs4 import BeautifulSoup
import copy
import re

class WebApplicationScanner:
    def __init__(self):
        self.vulnerabilities = []

    def scan_web_application(self, url):
        # Perform scanning for XSS vulnerabilities
        xss_vulnerabilities = self.scan_xss(url)
        self.vulnerabilities.extend(xss_vulnerabilities)

        # Perform scanning for SQL injection vulnerabilities
        sql_injection_vulnerabilities = self.scan_sql_injection(url)
        self.vulnerabilities.extend(sql_injection_vulnerabilities)

        # Perform scanning for remote command execution vulnerabilities
        rce_vulnerabilities = self.scan_rce(url)
        self.vulnerabilities.extend(rce_vulnerabilities)

        # Generate vulnerability report
        self.generate_report()

    def scan_xss(self, url):
        xss_vulnerabilities = []
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all input fields and check for potential XSS vulnerabilities
        input_fields = soup.find_all('input')
        for field in input_fields:
            payload = "<script>alert('XSS vulnerability')</script>"
            if self.test_payload(url, field, payload):
                xss_vulnerabilities.append(f"XSS vulnerability detected: {url}")

        return xss_vulnerabilities

    def scan_sql_injection(self, url):
        sql_injection_vulnerabilities = []
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links and check for potential SQL injection vulnerabilities
        links = soup.find_all('a', href=True)
        for link in links:
            payload = "1' OR '1'='1"
            if self.test_payload(url, link, payload):
                sql_injection_vulnerabilities.append(f"SQL injection vulnerability detected: {url}")

        return sql_injection_vulnerabilities

    def scan_rce(self, url):
        rce_vulnerabilities = []
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms and check for potential remote command execution vulnerabilities
        forms = soup.find_all('form')
        for form in forms:
            payload = "| cat /etc/passwd"
            if self.test_payload(url, form, payload):
                rce_vulnerabilities.append(f"Remote command execution vulnerability detected: {url}")

        return rce_vulnerabilities

    def test_payload(self, url, element, payload):
        # Create a deep copy of the original element and inject the payload
        modified_element = copy.deepcopy(element)
        modified_element.append(payload)

        # Submit the modified element and check if the payload is reflected in the response
        response = requests.get(url, params={element['name']: modified_element['value']})
        return re.search(payload, response.text, re.IGNORECASE) is not None

    def generate_report(self):
        print("=== Vulnerability Report ===")
        if self.vulnerabilities:
            for vulnerability in self.vulnerabilities:
                print(vulnerability)
        else:
            print("No vulnerabilities detected.")

# Example usage
scanner = WebApplicationScanner()
scanner.scan_web_application("https://example.com")
