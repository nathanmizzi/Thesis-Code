# Imports

import aspose.words as aw  # Used to create word document containing report
from datetime import datetime
from bs4 import BeautifulSoup as bs, MarkupResemblesLocatorWarning
from urllib.parse import urljoin
import requests
import pandas as pd
import warnings

# Variable Declarations
total_seconds = 0
successful_hit_type = []
hit_type = []

# Contains all the Base URL's of the webpages to test on

# It is important that the names of the sites below match the respective csv files name perfectly.
# list_of_source_csvs = ["BWAPP", "DVWA", "Mutillidae", "Orange_HRM", "Webgoat", "XVWA"]
list_of_source_csvs = ["Orange_HRM"]

urls_to_test = {}
vulnerable_urls = []
tested_urls = []

directoryListPath = "utils/directoryLists/dirbuster_200.txt"
passwordListPath = "utils/passwordLists/passlist.txt"
subdomainListPath = "utils/subdomainLists/subdomains.txt"
usernameListPath = "utils/usernameLists/usernames_small.txt"

# Utilities

def request(url):
    try:
        return requests.get(url.trim())
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.InvalidURL:
        print("Failed To Check URL: " + url)


def getCurrentDateTime():
    currentDate = datetime.now()
    return currentDate


def differenceInSeconds(stardDate, endDate):
    difference = (endDate - stardDate)

    return difference.total_seconds()


def generateReport(website_url):
    dateTimeToday = datetime.now().strftime('%d-%m-%Y_%H:%M:%S')

    report = aw.Document()
    builder = aw.DocumentBuilder(report)

    font = builder.font
    font.size = 24
    font.bold = True
    font.name = "Arial"
    font.underline = aw.Underline.SINGLE

    builder.write("\nPenetration Testing Report:\n\n")

    font.size = 16
    font.bold = False
    font.underline = aw.Underline.NONE

    builder.write(f"\nURL of Website: {website_url}\n")
    builder.write(f"\nDate and Time of Report: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}\n")

    builder.write(f"\nTotal Number Of attacks attempted: {len(hit_type)}\n")

    if len(hit_type) > 0:
        builder.write(f"\nAll Types of attacks attempted: {hit_type}\n")

    builder.write(f"\nNumber of Successful attacks: {len(successful_hit_type)}\n")

    if len(successful_hit_type) > 0:
        builder.write(f"\nTypes of Successful attacks: {successful_hit_type}\n")

    builder.write(f"\nTime taken to finish all attacks: {round(total_seconds, 2)} Seconds\n")

    font = builder.font
    font.size = 24
    font.bold = True
    font.name = "Arial"
    font.underline = aw.Underline.SINGLE

    builder.write(f"\nRecommendations: \n")

    font.size = 16
    font.bold = False
    font.underline = aw.Underline.NONE

    if "Email Brute-Forcer" or "Website Brute-Forcer" or "Directory Brute-Forcer" in successful_hit_type:
        builder.write("\nBrute Force: https://owasp.org/www-community/attacks/Brute_force_attack")

    if "DOS" in successful_hit_type:
        builder.write("\nDOS: https://owasp.org/www-community/attacks/Denial_of_Service")

    if "SQL Injection" in successful_hit_type:
        builder.write("\nSQL Injection: https://owasp.org/www-community/attacks/SQL_Injection")

    report.save(f"reports/report_{dateTimeToday}.docx")


def readCsv():

    websites_urls = []

    for file in list_of_source_csvs:
        df = pd.read_csv('utils/websiteLinks/' + file + '.csv')

        for index, row in df.iterrows():
            try:
                if df.iloc[index]["Processed"] == True and df.iloc[index]["Method"] == "GET":
                    # print(df.iloc[index]["URI"])
                    websites_urls.append(df.iloc[index]["URI"])
            except Exception as e:
                print(e)

        urls_to_test[file] = websites_urls

# Brute Forcers
def websiteBruteForce(page_url):
    with open(usernameListPath, "r") as usernames:

        for username in usernames:

            with open(passwordListPath, "r") as passwords:

                for password in passwords:

                    username = username.strip()
                    password = password.strip()
                    print(f"[!!] Trying To Brute Force With Username: '{username}', Password: '{password}'")

                    with requests.Session() as s:

                        resp = s.get(page_url)
                        parsed_html = bs(resp.content, features="html.parser")
                        input_value = parsed_html.body.find('input', attrs={'name': 'user_token'}).get("value")
                        data_dict = {"username": username, "password": password, "Login": "Login",
                                     "user_token": input_value}
                        response = s.post(page_url, data_dict)

                    if b"Login failed" in response.content:
                        pass
                    else:
                        print("\n[+] Username: --> " + username)
                        print("[+] Password: --> " + password)

                        return True

        print("\nUsername and password are not in wordlists.")
        return False


# SQL Injection

def get_all_forms(url):

    response = s.get(url)
    response_content = response.content

    soup = bs(response_content.decode('utf-8','ignore'), "html.parser")

    return soup.find_all("form")


def get_form_details(form):
    details = {}

    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    method = form.attrs.get("method", "get").lower()

    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    # print(details)
    return details


def isInjectable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "Uncaught mysqli_sql_exception"
    }

    for error in errors:
            if error in response.content.decode(errors='ignore').lower():
                return True

    return False


def sqlInjectionScan(url):

    if url not in tested_urls:

        forms = get_all_forms(url)

        if len(forms) >= 1:
            print(f"[+] Detected {len(forms)} forms on {url}.")

        for form in forms:
            form_details = get_form_details(form)

            try:
                if "xvwa" in url and form_details["inputs"][0]["name"] == "username": # Adding condition to skip login form for XVWA as it was causing issues
                    continue
            except:
                continue

            for c in "\"'":

                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # data[input_tag["name"]] = f"test{c}" # Old Code that only worked on dvwa
                        # TODO: Collect a dataset of SQL errors and iterate through a list of errors until one provides the required result, if none do, mark attempt as failed.
                          data[input_tag["name"]] = f"<1'1 or 1>" # New code that aims to catch more errors on a multitude of websites

                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    s.cookies.clear()
                    res = s.post(url, data=data)
                elif form_details["method"] == "get":
                    s.cookies.clear()
                    res = s.get(url, params=data)

                if isInjectable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    print(form_details)

                    tested_urls.append(url)

                    return True

    tested_urls.append(url)
    return False

# Website authenticators

def DVWA_test(urls):
    try:

        # Firstly, create a logged-in session in order to create requests

        s.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0',
            'Cookie': 'security=low; PHPSESSID=geo7gb3ehf5gfnbhrvuqu545i7'
        }

        resp = s.get('http://127.0.0.1/login.php')
        parsed_html = bs(resp.content, features="html.parser")
        input_value = parsed_html.body.find('input', attrs={'name': 'user_token'}).get("value")
        data_dict = {"username": 'admin', "password": 'password', "Login": "Login",
                     "user_token": input_value}

        response = s.post('http://127.0.0.1/login.php', data_dict)

        # Then test other urls

        for url in urls["DVWA"]:

            if sqlInjectionScan(url):

                vulnerable_urls.append("DVWA: " + url)

                if "SQL Injection" not in successful_hit_type:
                    successful_hit_type.append("SQL Injection")

    except Exception as e:
        print("\nDVWA Error: \n")
        print(e)

def XVWA_test(urls):
    try:

        for url in urls["XVWA"]:

            if sqlInjectionScan(url):

                if url not in vulnerable_urls:
                    vulnerable_urls.append("XVWA: " + url)

                if "SQL Injection" not in successful_hit_type:
                    successful_hit_type.append("SQL Injection")

    except Exception as e:
        print("\nXVWA Error: \n")
        print(e)

def OrangeHRM_test(urls):
    try:

        # Firstly, create a logged-in session in order to create requests

        s.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0',
            'Cookie': 'security=low; PHPSESSID=geo7gb3ehf5gfnbhrvuqu545i7'
        }

        resp = s.get('http://localhost:1234/OrangeHRM/symfony/web/index.php/auth/login')
        parsed_html = bs(resp.content, features="html.parser")
        data_dict = {"txtUsername": 'admin', "txtPassword": 'Mcast1234!', "Submit": "LOGIN"}

        response = s.post("http://localhost:1234/OrangeHRM/symfony/web/index.php/auth/validateCredentials", data_dict)

        responseContent = response.content.decode()

        print("Breakpoint!");

        # Then test other urls

        for url in urls["Orange_HRM"]:

            if sqlInjectionScan(url):

                if url not in vulnerable_urls:
                    vulnerable_urls.append("Orange_HRM: " + url)

                if "SQL Injection" not in successful_hit_type:
                    successful_hit_type.append("SQL Injection")

    except Exception as e:
        print("\nOrange_HRM Error: \n")
        print(e)

if __name__ == '__main__':

    warnings.filterwarnings(action="ignore", category=MarkupResemblesLocatorWarning)

    # Populate array of urls from csv files
    readCsv()

    # Test urls accordingly
    with requests.Session() as s:

        DVWA_test(urls_to_test)

        XVWA_test(urls_to_test)

        OrangeHRM_test(urls_to_test)


    # Urls have been tested, now output the results to the user.

    print("\nVulnerabilities were found with: " + str(len(vulnerable_urls)) + " urls.")

    for url in vulnerable_urls:
        print("Vulnerable URL: " + url)

