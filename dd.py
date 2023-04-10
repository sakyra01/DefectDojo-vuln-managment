import re
from decouple import config
import requests
import logging
from pyExploitDb import PyExploitDb
from tenable import tenable_serf, www
import json


# On Logger + updating db pyExploitDB
pEdb = PyExploitDb()
pEdb.debug = False
Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(filename="logfile.log",
                    filemode="w",
                    format=Log_Format,
                    level=logging.INFO)
logger = logging.getLogger()


def get_request():
    uri = config('URL')  # your dd api uri
    token = config('Token')  # your dd api token
    headers = {'content-type': 'application/json', 'Authorization': token}
    content = requests.get(uri, headers=headers, verify=True)  # set verify to False if ssl cert is self-signed
    return content


def post_request(tags, finding_id):
    uri = config('POST_URL')  # path to api finding id + tags
    uri = f'{uri}{finding_id}/tags/'  # sum full path
    token = config('Token')  # your dd api token
    body = {"tags": tags}
    headers = {'content-type': 'application/json', 'Authorization': token}
    requests.post(uri, headers=headers, verify=True, json=body)


def regex(lines):
    for line in lines:
        if re.match(r"CVE-\d{4}-\d{4,7}", line) or re.match(r"(?i)\bcve-\d{4}-\d{4,7}", line):
            return line


def tenable_enumeration(cve):
    tenable_url = f'https://www.tenable.com/plugins/search?q=%22{cve}%22&sort=vpr_score&page=1'
    middle_page = tenable_serf(tenable_url)
    tenable_page = www(middle_page)
    js_payload = json.dumps(tenable_page, indent=4)
    return js_payload


def find_cve_fields(field):
    catcher = regex(field)
    return catcher


def tenable(cve, finding_id):
    cve_tenable = tenable_enumeration(cve)  # Call function which parsing tenable source
    if cve_tenable == "{}":
        logger.error(f"Information in Tenable does not exist for finding - {finding_id}")
        return
    else:
        logger.error(f"Made Tenable Tag for finding - {finding_id}")
        return cve_tenable


def exploitdb(cve, finding_id):
    cve_db = pEdb.searchCve(cve)  # Searching cve value in pEdb databases
    if len(cve_db) != 0:
        cve_db_references = f"{finding_id}: https://www.exploit-db.com/exploits/{cve_db['id']}"
        logger.info(f"Made Exploit-DB tag for finding - {finding_id}")
        return cve_db_references
    else:
        logger.error(f"Exploit for {cve} does not exist")
        return


def enumeration():
    results = r.json()['results']
    cve = ''  # cve value is empty
    tenable_list = {}
    exploitdb_ref = None
    tags = []

    for finding in range(len(results)):
        finding_id = results[finding]['id']
        finding_title = results[finding]['title']
        finding_description = results[finding]['description']
        finding_references = results[finding]['references']
        vulnerability_ids = results[finding]['vulnerability_ids']
        finding_tags = results[finding]['tags']

        if len(vulnerability_ids) != 0:     # condition if cve in fields
            cve = vulnerability_ids[0]['vulnerability_id']
            tenable_list = tenable(cve, finding_id)
            exploitdb_ref = exploitdb(cve, finding_id)
        else:  # condition to find cve in fields
            if len(finding_title) != 0 and cve == '':
                cve = find_cve_fields(finding_title)
                tenable_list = tenable(cve, finding_id)
                exploitdb_ref = exploitdb(cve, finding_id)
            elif len(finding_description) != 0 and cve == '':
                cve = find_cve_fields(finding_description)
                tenable_list = tenable(cve, finding_id)
                exploitdb_ref = exploitdb(cve, finding_id)
            elif len(finding_references) != 0 and cve == '':
                cve = find_cve_fields(finding_references)
                tenable_list = tenable(cve, finding_id)
                exploitdb_ref = exploitdb(cve, finding_id)
            else:
                logger.error(f"CVE value didn't find in finding - {finding_id}")

        # Condition if tag in finding, don't touch it
        if tenable_list != "{}" and "tenable-db" not in finding_tags:
            tenable_tag = "tenable-db"
            tags.append(tenable_tag)
        if exploitdb_ref is not None and "exploit-db" not in finding_tags:
            exploitdb_tag = "exploit-db"
            tags.append(exploitdb_tag)
        if tags is not None:
            post_request(tags, finding_id)


if __name__ == '__main__':
    logger.info("=== START script ===")  # Start script

    # Update DB exploit-db from https://gitlab.com/exploit-database/exploitdb
    try:
        pEdb.openFile()
        logger.info("exploit-db local DB updated successfully")
    except RuntimeError:
        logger.error("exploit-db can't update")

    # Checking connection to API DefectDojo
    try:
        r = get_request()
        logger.info("Successfully obtained all vulnerabilities")
    except ConnectionError:
        logger.error("Connection error")

    # Checking status of response page and switch to function workers
    if r.status_code == 200:
        enumeration()
    else:
        logger.error("Response failed. Status code is " + str(r.status_code))
    logger.info("=== STOP  script ===")
