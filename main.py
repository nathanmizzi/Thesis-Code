# Imports
import math
from datetime import datetime
from bs4 import BeautifulSoup as bs, MarkupResemblesLocatorWarning, XMLParsedAsHTMLWarning
from urllib.parse import urljoin
import requests
import pandas as pd
import warnings
import uuid as uid
from matplotlib import pyplot as plt
from docx import Document
from docx.shared import Inches

# Metrics for pdf generation:
total_seconds = 0
successful_hit_type = {}
hit_type = []
sqliStringsPerWebsite = {}
sqliStringsAttemptedInTotal = 0

safeWebPagesInSite = {}
vulnerableWebPagesInSite = {}

# A Dictionary containing dataframes which contain info regarding a website
reportDetails = {}

# Contains all the Base URL's of the webpages to test on

# It is important that the names of the sites below match the respective csv files name perfectly.
# list_of_source_csvs = ["BWAPP", "DVWA", "Mutillidae", "Orange_HRM", "Webgoat", "XVWA"]
list_of_source_csvs = ["DVWA", "XVWA"]

urls_to_test = {}
vulnerable_urls = []
sqliStrings = []
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


def generateReports():

    dateTimeToday = datetime.now().strftime('%d-%m-%Y_%H:%M:%S')

    report = Document()

    h1 = report.add_heading("\nPenetration Testing Report:", 0)
    h1.bold = True

    for website in list_of_source_csvs:

        websiteHeader = report.add_paragraph(f"\nWebsite Tested: {website}")
        websiteHeader.bold = True

        report.add_paragraph(f"\nDate and Time of Report: {datetime.now().strftime('%d-%m-%Y, %H:%M:%S')}")

        report.add_paragraph(f"\nTotal Number Of Injection attacks attempted: {len(hit_type)}")

        if len(hit_type) > 0:
            report.add_paragraph(f"\nAll Types of attacks attempted: {hit_type}")

        report.add_paragraph(f"\nNumber of Successful attacks: {len(successful_hit_type[website])}")

        if len(successful_hit_type[website]) > 0:
            report.add_paragraph(f"\nTypes of Successful attacks: {successful_hit_type[website]}")

            sqliParagraphString = f"\nSQLI Strings Used: "

            for injectionString in sqliStringsPerWebsite[website]:
                sqliParagraphString += injectionString + ','

            sqliParagraphString = sqliParagraphString[:-1]
            sqliParagraphString += '.'

            report.add_paragraph(sqliParagraphString)

        report.add_paragraph(f"\nTime taken to finish all attacks: {str(math.ceil(total_seconds))} Seconds\n")

        report.add_paragraph(f"\nVulnerability Statistics: ")
        # Creating a Pie Chart of vulnerable and safe code.
        lbls = ["Vulnerable", "Safe"]
        id_of_img = uid.uuid1().__str__()
        fig = plt.figure(figsize= (3, 2))
        plt.pie([len(vulnerableWebPagesInSite[website]), len(safeWebPagesInSite[website])], labels=lbls,
                autopct='%1.1f%%', shadow=True, startangle=90)

        plt.savefig('utils/graphs/' + id_of_img + ".png")
        report.add_picture('utils/graphs/' + id_of_img + ".png", width=Inches(3), height=Inches(2))

        report.add_paragraph(f"\nRecommendations: ")

        for string in successful_hit_type[website]:
            if "SQL Injection" in string:
                recommendedPar = report.add_paragraph("SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection")
                recommendedParFormat = recommendedPar.paragraph_format
                recommendedParFormat.left_indent = Inches(0.5)

        report.add_page_break()

        report.save(f"reports/report_{dateTimeToday}.docx")

def readWebsiteLinksCsv():

    for fileName in list_of_source_csvs:

        websites_urls = []

        df = pd.read_csv('utils/websiteLinks/' + fileName + '.csv')

        for index, row in df.iterrows():
            try:
                if df.iloc[index]["Processed"] == True and df.iloc[index]["Method"] == "GET":
                    # print(df.iloc[index]["URI"])
                    websites_urls.append(df.iloc[index]["URI"])
            except Exception as e:
                print(e)

        urls_to_test[fileName] = websites_urls

def readSQLICsv():

    df = pd.read_csv('utils/SQLI_Dataset/SQLIV3_Shrunken.csv')

    for index, row in df.iterrows():
        try:
            sqliStrings.append(df.iloc[index]["Sentence"])
        except Exception as e:
            print(e)

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

def get_all_forms(url, cookies):

    if cookies is not None:
        response = s.get(url, cookies=cookies)
        response_content = response.content

        soup = bs(response_content.decode('utf-8', 'ignore'), "html.parser")

        return soup.find_all("form")
    else:
        response = s.get(url)
        response_content = response.content

        soup = bs(response_content.decode('utf-8', 'ignore'), "html.parser")

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
        "Uncaught mysqli_sql_exception",
        "unexpected token"
    }

    for error in errors:
        if response.status_code != 404:
            if error in response.content.decode(errors='ignore').lower():
                return True

    return False

def sqlInjectionScan(url, cookies, nameOfWebsite):

    for sqliString in sqliStrings:
        if url not in tested_urls:

            forms = get_all_forms(url, cookies)

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
                              # data[input_tag["name"]] = f"<1'1 or 1>" # New code that aims to catch more errors on a multitude of websites
                              data[input_tag["name"]] = sqliString  # Takes a string from the Dataset containing sqli strings.

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

                        sqliStringsPerWebsite[nameOfWebsite].append(sqliString)
                        tested_urls.append(url)

                        return True

    tested_urls.append(url)
    return False

# Website authenticators

def DVWA_sqli(urls):
    try:

        successful_hit_type["DVWA"] = []

        vulnerableWebPagesInSite["DVWA"] = []
        safeWebPagesInSite["DVWA"] = []
        hit_type.append("Error Based SQL Injection")

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
        cookies = response.cookies

        # Then test other urls

        for url in urls["DVWA"]:

            if sqlInjectionScan(url, cookies, "DVWA"):

                vulnerableWebPagesInSite["DVWA"].append(url)

                vulnerable_urls.append("DVWA: " + url)

                if "SQL Injection" not in successful_hit_type["DVWA"]:
                    successful_hit_type["DVWA"].append("Error Based SQL Injection")
            else:
                safeWebPagesInSite["DVWA"].append(url)

    except Exception as e:
        print("\nDVWA Error: \n")
        print(e)

def XVWA_sqli(urls):

    try:

        successful_hit_type["XVWA"] = []

        vulnerableWebPagesInSite["XVWA"] = []
        safeWebPagesInSite["XVWA"] = []
        hit_type.append("Error Based SQL Injection")

        for url in urls["XVWA"]:

            if sqlInjectionScan(url, None, "XVWA"):
                vulnerableWebPagesInSite["XVWA"].append(url)

                if url not in vulnerable_urls:
                    vulnerable_urls.append("XVWA: " + url)

                if "SQL Injection" not in successful_hit_type["XVWA"]:
                    successful_hit_type["XVWA"].append("Error Based SQL Injection")

            else:
                safeWebPagesInSite["XVWA"].append(url)

    except Exception as e:
        print("\nXVWA Error: \n")
        print(e)

def OrangeHRM_test(urls):
    try:

        successful_hit_type["Orange_HRM"] = []

        # Firstly, create a logged-in session in order to create requests
        resp = s.get('http://localhost:1234/OrangeHRM/symfony/web/index.php/auth/login')
        parsed_html = bs(resp.content, features="html.parser")
        input_value = parsed_html.body.find('input', attrs={'name': '_csrf_token'}).get("value")
        data_dict = {"txtUsername": 'admin', "txtPassword": 'Mcast1234!', "Submit": "LOGIN", "_csrf_token":input_value}

        response = s.post("http://localhost:1234/OrangeHRM/symfony/web/index.php/auth/validateCredentials", data_dict)
        cookies = response.cookies
        response_content = response.content.decode()

        # Then test other urls

        for url in urls["Orange_HRM"]:

            try:
                if sqlInjectionScan(url, cookies, "Orange_HRM"):

                    if url not in vulnerable_urls:
                        vulnerable_urls.append("Orange_HRM: " + url)

                    if "SQL Injection" not in successful_hit_type["Orange_HRM"]:
                        successful_hit_type["Orange_HRM"].append("SQL Injection")
            except:
                continue

    except Exception as e:
        print("\nOrange_HRM Error: \n")
        print(e)

def Mutillidae_test(urls):
    try:

        successful_hit_type["Mutillidae"] = []

        for url in urls["Mutillidae"]:

            if sqlInjectionScan(url, None, "Mutillidae"):

                if url not in vulnerable_urls:
                    vulnerable_urls.append("Mutillidae: " + url)

                if "SQL Injection" not in successful_hit_type["Mutillidae"]:
                    successful_hit_type["Mutillidae"].append("SQL Injection")

    except Exception as e:
        print("\nMutillidae Error: \n")
        print(e)

def WebGoat_test(urls):
    try:

        successful_hit_type["Webgoat"] = []

        # Firstly, create a logged-in session in order to create requests
        s.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'
        }

        resp = s.get('http://localhost:8080/WebGoat/login')
        parsed_html = bs(resp.content, features="html.parser")
        data_dict = {"username": 'nathanmizzi', "password": 'mcast1234'}

        response = s.post("http://localhost:8080/WebGoat/login", data_dict)

        response_content = response.content.decode()
        cookies = s.cookies.get_dict()

        # Then test other urls

        for url in urls["Webgoat"]:

            if sqlInjectionScan(url, cookies, "Webgoat"):

                if url not in vulnerable_urls:
                    vulnerable_urls.append("Webgoat: " + url)

                if "SQL Injection" not in successful_hit_type["Webgoat"]:
                    successful_hit_type["Webgoat"].append("SQL Injection")

    except Exception as e:
        print("\nWebgoat Error: \n")
        print(e)

if __name__ == '__main__':

    warnings.filterwarnings(action="ignore", category=MarkupResemblesLocatorWarning)
    warnings.filterwarnings(action="ignore", category=XMLParsedAsHTMLWarning)

    # Get the current time before all tests start
    timeStarted = getCurrentDateTime()

    # Populate array of urls from csv files
    readWebsiteLinksCsv()

    # Populate array of SQL Injection strings from Kaggle Dataset
    readSQLICsv()

    # Test urls accordingly
    with requests.Session() as s:
        sqliStringsPerWebsite["DVWA"] = []
        DVWA_sqli(urls_to_test)

    with requests.Session() as s:
        sqliStringsPerWebsite["XVWA"] = []
        XVWA_sqli(urls_to_test)

    with requests.Session() as s:
        sqliStringsPerWebsite["Orange_HRM"] = []
        OrangeHRM_test(urls_to_test)

    with requests.Session() as s:
        sqliStringsPerWebsite["Mutillidae"] = []
        Mutillidae_test(urls_to_test)

    with requests.Session() as s:
        sqliStringsPerWebsite["WebGoat"] = []
        WebGoat_test(urls_to_test)

    # Get the current time when all tests end
    timeEnded = getCurrentDateTime()

    # Calculate the difference in seconds between the start and the end times
    total_seconds += differenceInSeconds(timeStarted, timeEnded)

    # Generate Reports
    generateReports()

    # Urls have been tested, now output the results to the user.
    print("\nVulnerabilities were found with: " + str(len(vulnerable_urls)) + " urls.")
    print("Total Time Taken To Perform Tests: " + str(math.ceil(total_seconds)) + " Seconds")

    for url in vulnerable_urls:
        print("Vulnerable URL in " + url)

