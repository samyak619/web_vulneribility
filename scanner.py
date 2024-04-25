import re
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

class Scanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links

    def extract_links_from(self, url):
        response = self.session.get(url)
        if response.status_code == 200:
            page_content = response.content.decode("utf-8")
            return re.findall('(?:href=")(.*?)"', page_content)
        else:
            print("Failed to retrieve page:", url)
            return []

    def crawl(self, url=None):
        if url is None:
            url = self.target_url
        href_links = self.extract_links_from(url)
        for link in href_links:
            link = urljoin(url, link)
            if "#" in link:
                link = link.split("#")[0]
            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)

    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, "html.parser")
        return parsed_html.find_all("form")

    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urljoin(url, action)
        method = form.get("method")

        input_list = form.find_all("input")
        post_data = {}
        for input in input_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")
            if input_type == "text":
                input_value = value

            post_data[input_name] = input_value

        if method == "post":
            return self.session.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def run_scanner(self):
        output = ""
        for link in self.target_links:
            forms = self.extract_forms(link)
            for form in forms:
                output += f"[+] Testing form in {link}<br>"
                is_vulnerable_to_XSS = self.test_xss_in_form(form, link)
                if is_vulnerable_to_XSS:
                    output += f"\n\n[+] XSS discovered in {link} in the following form<br>{str(form)}<br><br>"
            if "=" in link:
                output += f"[+] Testing {link}<br>"
                is_vulnerable_to_XSS = self.test_XSS_in_link(link)
                if is_vulnerable_to_XSS:
                    output += f"\n\n[+] discovered XSS in {link}<br>"
                output += f"[+] Testing for GET SQL in {link}<br>"

            for form in forms:
                output += f"Testing POST SQL injection attack concerning bypass login in {link}<br>"
                is_vulnerable_to_SQL = self.test_sql_injection_with_OR(form, link)
                if is_vulnerable_to_SQL:
                    output += f"\n\n[+] discovered login bypass SQL in {link}<br>{str(form)}<br><br>"

        return output

    def test_XSS_in_link(self, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        url = url.replace("=", "=" + xss_test_script)
        response = self.session.get(url)
        xss_test_script_bytes = xss_test_script.encode(response.encoding)  # Encode the string to bytes
        return xss_test_script_bytes in response.content

    def test_xss_in_form(self, form, url):
        xss_test_script = "<sCript>alert('test')</scriPt>"
        response = self.submit_form(form, xss_test_script, url)
        xss_test_script_bytes = xss_test_script.encode(response.encoding)  # Encode the string to bytes
        return xss_test_script_bytes in response.content

    def test_sql_injection_with_OR(self, form, url):
        sql_test_script = "password' or 1=1#"
        response = self.submit_form(form, sql_test_script, url)
        sql_test_script_bytes = sql_test_script.encode(response.encoding)  # Encode the string to bytes
        return sql_test_script_bytes in response.content