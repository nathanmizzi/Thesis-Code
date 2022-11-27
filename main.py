# Imports

import pyautogui
import aspose.words as aw  # Used to create word document containing report
from datetime import datetime
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests

# Variable Declarations
Thesis = True
total_seconds = 0
successful_hit_type = []
hit_type = []

# Contains all the Base URL's of the webpages to test on
list_of_source_urls = ["http://127.0.0.1", "http://localhost:8080/WebGoat", "https://127.0.0.1/xvwa"]

# DVWA Links

root_url = "http://127.0.0.1/"
website_url = "http://127.0.0.1"
login_page = "http://127.0.0.1/login.php"
sqli_page = "http://127.0.0.1/vulnerabilities/sqli/"

# Mutillidae Links

# root_url = "http://192.168.56.101"
# website_url = "http://192.168.56.101/mutillidae"
# login_page = "http://192.168.56.101/mutillidae/index.php?page=login.php"
# sqli_page = "http://192.168.56.101/mutillidae/index.php?page=register.php"

directoryListPath = "utils/directoryLists/dirbuster_200.txt"
passwordListPath = "utils/passwordLists/passlist.txt"
subdomainListPath = "utils/subdomainLists/subdomains.txt"
usernameListPath = "utils/usernameLists/usernames_small.txt"

listOfFunctionalities = ["Website Brute-Forcer", "Directory Brute-Forcer",
                         "Sub Domain Brute-Forcer", "SQL Injection Scan", "Generate Report", "Exit"]

# Utilities
def webcrawler():

    urls_to_crawl = []

    for url in list_of_source_urls:
        urls_to_crawl.append(automatedWebDirectoryFinder(url))

    print("\n These URL's were obtained!")
    print(urls_to_crawl)

def request(url):
    try:
        return requests.get(url)
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

def menuMaker():

    try:
        cnt = 0
        for functionality in listOfFunctionalities:
            cnt = cnt + 1
            print(f"[{cnt}] {functionality}")

        userInp = int(input("\nPlease Select The number of the functionality you would like to use: "))
        userInp = userInp - 1

        if userInp >= 0 and userInp <= len(listOfFunctionalities):
            return listOfFunctionalities[userInp]
        else:
            return None
    except Exception:
        return None

def generateReport():

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

    builder.write(f"\nTime taken to finish all attacks: {round(total_seconds,2)} Seconds\n")

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

def displayMenuSelector():
    while True:

        methodChosen = menuMaker()

        if methodChosen == "Website Brute-Forcer":

            if "Website Brute-Forcer" not in hit_type:
                hit_type.append("Website Brute-Forcer")

            dateTimeStart = getCurrentDateTime()

            if websiteBruteForce(login_page):

                if "Website Log-in Brute Force" not in successful_hit_type:
                    successful_hit_type.append("Website Log-in Brute Force")

            dateTimeEnd = getCurrentDateTime()
            total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

        elif methodChosen == "Directory Brute-Forcer":

            if "Directory Brute-Forcer" not in hit_type:
                hit_type.append("Directory Brute-Forcer")

            dateTimeStart = getCurrentDateTime()

            if webDirectoryFinder(website_url):
                if "Directory Brute Force" not in successful_hit_type:
                    successful_hit_type.append("Directory Brute Force")

            dateTimeEnd = getCurrentDateTime()
            total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

        elif methodChosen == "Sub Domain Brute-Forcer":

            if "Sub Domain Brute-Forcer" not in hit_type:
                hit_type.append("Sub Domain Brute-Forcer")

            dateTimeStart = getCurrentDateTime()

            if subDomainsFinder(website_url):
                if "Sub Domain Brute Force" not in successful_hit_type:
                    successful_hit_type.append("Sub Domain Brute Force")

            dateTimeEnd = getCurrentDateTime()
            total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

        elif methodChosen == "SQL Injection Scan":

            if "SQL Injection" not in hit_type:
                hit_type.append("SQL Injection")

            dateTimeStart = getCurrentDateTime()

            with requests.Session() as s:

                s.headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0',
                    'Cookie': 'security=low; PHPSESSID=geo7gb3ehf5gfnbhrvuqu545i7'
                }

                resp = s.get(login_page)
                parsed_html = bs(resp.content, features="html.parser")
                input_value = parsed_html.body.find('input', attrs={'name': 'user_token'}).get("value")
                data_dict = {"username": 'admin', "password": 'password', "Login": "Login",
                             "user_token": input_value}

                response = s.post(login_page, data_dict)

                if sqlInjectionScan(sqli_page):
                    if "SQL Injection" not in successful_hit_type:
                        successful_hit_type.append("SQL Injection")

            dateTimeEnd = getCurrentDateTime()
            total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

        elif methodChosen == "Generate Report":
            generateReport()

        elif methodChosen == "Exit":
            exit()

        elif methodChosen is None:
            print("An Invalid Option Was Inputted, Please Try Again")

        input("\nPress Enter To Continue...")
        pyautogui.hotkey('shift', 'l')  # Clears the pycharm console, will not work unless Clear All hotkey is set

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

# Finders

def webDirectoryFinder(page_url):

    dirFound = False

    target_url = page_url

    print("\nBeginning Web Directory Brute-Force...\n")

    file = open(directoryListPath,"r")

    for line in file:
        word = line.strip()
        full_url = target_url + "/" + word
        response = request(full_url)

        if response:
            print("[+] Discovered Directory At This Link: " + full_url)
            dirFound = True

    return  dirFound

def automatedWebDirectoryFinder(page_url):

    list_of_directories = []

    target_url = page_url

    print("\nBeginning Web Directory Brute-Force...\n")

    file = open(directoryListPath, "r")

    list_of_attempted_urls = []

    for line in file:
        word = line.strip()
        full_url = target_url + "/" + word
        list_of_attempted_urls.append(full_url)
        response = request(full_url)

        if response:

            if response.history:

                directory_found = response.url.split(target_url + "/")

                print("Request was redirected")

                # Final Destination -
                print(response.status_code, response.url)

                if word != directory_found[1].strip("/"):
                    print("Redirect led to login page, ignoring...")
                else:
                    print("[+] Discovered Directory At This Link: " + full_url)
                    list_of_directories.append(full_url)
            else:
                print("[+] Discovered Directory At This Link: " + full_url)
                list_of_directories.append(full_url)

        else:
            print("[-] Failed To Find Directory At This Link: " + full_url)

    for subdirectory in list_of_attempted_urls:

        file = open(directoryListPath, "r")

        for line in file:
            word = line.strip()
            full_url = subdirectory + "/" + word
            response = request(full_url)

            if response:

                if response.history:

                    directory_found = response.url.split(target_url + "/")

                    print("Request was redirected")

                    # Final Destination -
                    print(response.status_code, response.url)

                    if word not in subdirectory:
                        if word != directory_found[1].strip("/"):
                            print("Redirect led to login page, ignoring...")
                        else:
                            print("[+] Discovered Directory At This Link: " + full_url)
                            list_of_directories.append(full_url)
                    else:
                        print("Skipped as Duplicate..")
                else:
                    print("[+] Discovered Directory At This Link: " + full_url)
                    list_of_directories.append(full_url)

            else:
                print("[-] Failed To Find Directory At This Link: " + full_url)

    return list_of_directories

def subDomainsFinder(page_url):

    subDomainFound = False

    target_url = page_url
    target_url = target_url.replace("http://", "")

    print("\nBeginning Sub Domain Brute-Force...\n")

    file = open(subdomainListPath,"r")

    for line in file:
        word = line.strip()
        full_url = word + "." + target_url
        response = request("http://" + full_url)

        if response:
            print("[+] Discovered Subdomain At This Link: " + full_url)
            subDomainFound = True

    return subDomainFound


# SQL Injection

def get_all_forms(url):

    soup = bs(s.get(url).content, "html.parser")

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
        "quoted string not properly terminated"
    }

    for error in errors:
        if error in response.content.decode().lower():
            return True

    return False


def sqlInjectionScan(url):

    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":

            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:

                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

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
                return True

    return False


if __name__ == '__main__':

    if not Thesis:
        while True:
            methodChosen = menuMaker()

            if methodChosen == "Website Brute-Forcer":

                if "Website Brute-Forcer" not in hit_type:
                    hit_type.append("Website Brute-Forcer")

                dateTimeStart = getCurrentDateTime()

                if websiteBruteForce(login_page):

                    if "Website Log-in Brute Force" not in successful_hit_type:
                        successful_hit_type.append("Website Log-in Brute Force")

                dateTimeEnd = getCurrentDateTime()
                total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

            elif methodChosen == "Directory Brute-Forcer":

                if "Directory Brute-Forcer" not in hit_type:
                    hit_type.append("Directory Brute-Forcer")

                dateTimeStart = getCurrentDateTime()

                if webDirectoryFinder(website_url):
                    if "Directory Brute Force" not in successful_hit_type:
                        successful_hit_type.append("Directory Brute Force")

                dateTimeEnd = getCurrentDateTime()
                total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

            elif methodChosen == "Sub Domain Brute-Forcer":

                if "Sub Domain Brute-Forcer" not in hit_type:
                    hit_type.append("Sub Domain Brute-Forcer")

                dateTimeStart = getCurrentDateTime()

                if subDomainsFinder(website_url):
                    if "Sub Domain Brute Force" not in successful_hit_type:
                        successful_hit_type.append("Sub Domain Brute Force")

                dateTimeEnd = getCurrentDateTime()
                total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

            elif methodChosen == "SQL Injection Scan":

                if "SQL Injection" not in hit_type:
                    hit_type.append("SQL Injection")

                dateTimeStart = getCurrentDateTime()

                with requests.Session() as s:

                    s.headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0',
                        'Cookie': 'security=low; PHPSESSID=geo7gb3ehf5gfnbhrvuqu545i7'
                    }

                    resp = s.get(login_page)
                    parsed_html = bs(resp.content, features="html.parser")
                    input_value = parsed_html.body.find('input', attrs={'name': 'user_token'}).get("value")
                    data_dict = {"username": 'admin', "password": 'password', "Login": "Login",
                                 "user_token": input_value}

                    response = s.post(login_page, data_dict)

                    if sqlInjectionScan(sqli_page):
                        if "SQL Injection" not in successful_hit_type:
                            successful_hit_type.append("SQL Injection")

                dateTimeEnd = getCurrentDateTime()
                total_seconds = total_seconds + differenceInSeconds(dateTimeStart, dateTimeEnd)

            elif methodChosen == "Generate Report":
                generateReport()

            elif methodChosen == "Exit":
                exit()

            elif methodChosen is None:
                print("An Invalid Option Was Inputted, Please Try Again")

            input("\nPress Enter To Continue...")
            pyautogui.hotkey('shift', 'l')  # Clears the pycharm console, will not work unless Clear All hotkey is set
    else:
        webcrawler()