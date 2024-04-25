#!usr/bin/env python

import scanner as scanner

target_url = "https://www.flipkart.com/"
links_to_ignore = [""]
# If initial scan scans a logout url, you'd want to include it in here so that you dont lose the post session

data_dict = {"username": "admin", "password": "password", "Login": "submit"}
# this is for if loggin in will get you more links and you know the login info

vulnerabilities_scanner = scanner.Scanner(target_url, links_to_ignore)
vulnerabilities_scanner.session.post("https://www.flipkart.com/", data=data_dict) # this is the link to which the scanner will login and store as post

vulnerabilities_scanner.crawl()
vulnerabilities_scanner.run_scanner()