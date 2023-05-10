import re
import time
from tenable import tenable_serf, www
from connection import check_connection, get_request, post_request, logger, pEdb


def regex(line):
    new_line = line.split()
    for li in new_line:
        result = re.search(r"CVE-\d{4}-\d{4,7}", li)
        if result is not None:
            return result.group(0)


def tenable_enumeration(cve):
    tenable_url = f'https://www.tenable.com/plugins/search?q=%22{cve}%22&sort=vpr_score&page=1'
    time.sleep(10)  # bypassing request block possibility
    middle_page = tenable_serf(tenable_url)
    if middle_page is not None:
        tenable_page = www(middle_page)
        return tenable_page
    else:
        return middle_page


def find_cve_fields(field):
    catcher = regex(field)
    return catcher


def tenable(cve, finding_id):
    tenable_data = []
    cve_tenable = tenable_enumeration(cve)  # Call function which parsing tenable source
    if cve_tenable is None:
        logger.error(f"Information in Tenable does not exist for finding-{finding_id}")
        return
    else:
        for x in cve_tenable:
            if x == 'Exploit Available' and cve_tenable[x] == ' true':
                tenable_tag = True
                tenable_data.append(tenable_tag)
                logger.info(f"Made tenable-db tag for finding-{finding_id}")
            if x == 'Risk':
                tenable_score = f"VPR_{cve_tenable[x]}"
                tenable_data.append(tenable_score)
                logger.info(f"Made {tenable_score} tag for finding-{finding_id}")
        return tenable_data


def exploitdb(cve, finding_id):
    cve_db = pEdb.searchCve(cve)  # Searching cve value in pEdb databases
    if len(cve_db) != 0:
        cve_db_references = f"https://www.exploit-db.com/exploits/{cve_db['id']}"
        logger.info(f"Exploit link-{cve_db_references} for finding-{finding_id}")
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
            if len(finding_title) != 0 and cve is None:
                cve = find_cve_fields(finding_title)
                if cve is not None:
                    tenable_list = tenable(cve, finding_id)
                    exploitdb_ref = exploitdb(cve, finding_id)
            if len(finding_description) != 0 and cve is None:
                cve = find_cve_fields(finding_description)
                if cve is not None:
                    tenable_list = tenable(cve, finding_id)
                    exploitdb_ref = exploitdb(cve, finding_id)
            if len(finding_references) != 0 and cve is None:
                cve = find_cve_fields(finding_references)
                if cve is not None:
                    tenable_list = tenable(cve, finding_id)
                    exploitdb_ref = exploitdb(cve, finding_id)
            if cve is None:
                logger.error(f"CVE didn't find in finding-{finding_id}")

        # # Uncomment when we need add tags to findings (active phase)
        # if tenable_list != "{}" and "tenable-db" not in finding_tags:
        #     tenable_tag = "tenable-db"
        #     tags.append(tenable_tag)
        # if exploitdb_ref is not None and "exploit-db" not in finding_tags:
        #     exploitdb_tag = "exploit-db"
        #     tags.append(exploitdb_tag)
        # if tags is not None:
        #     post_request(tags, finding_id)


if __name__ == '__main__':
    logger.info("=== START script ===")  # Start script

    # Update DB exploit-db from https://gitlab.com/exploit-database/exploitdb
    try:
        pEdb.openFile()
        logger.info("Exploit-db local DB updated successfully")
    except RuntimeError:
        logger.error("Exploit-db can't update")

    # Checking connection to API DefectDojo
    try:
        check_connection()
        logger.info("Successfully obtained all vulnerabilities")
    except ConnectionError:
        logger.error("Connection error")

    # Checking status of response page and switch to function workers
    num = check_connection()
    r = get_request(num)
    if r.status_code == 200:
        enumeration()
    else:
        logger.error("Response failed. Status code is " + str(r.status_code))
    logger.info("=== STOP  script ===")
