from dotenv import load_dotenv
import os
import requests
from pyExploitDb import PyExploitDb
import logging
from datetime import datetime


# On Logger + updating db pyExploitDB
timestamp = datetime.today().strftime('%Y-%m-%d')
load_dotenv()  # look in .env
pEdb = PyExploitDb()
pEdb.debug = False
Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(filename=f"logs/logfile_{timestamp}.log", filemode="w", format=Log_Format, level=logging.INFO)
logger = logging.getLogger()


def check_connection():
    uri = os.getenv('URL')  # your dd api uri
    token = os.getenv('Token')  # your dd api token
    headers = {'content-type': 'application/json', 'Authorization': token}
    content = requests.get(uri, headers=headers, verify=True)  # set verify to False if ssl cert is self-signed
    c = content.json()["count"]
    return c


def get_request(count):
    uri = os.getenv('URL')  # your dd api uri
    uri = f'{uri}?limit={count}&offset={count}/'
    token = os.getenv('Token')  # your dd api token
    headers = {'content-type': 'application/json', 'Authorization': token}
    content = requests.get(uri, headers=headers, verify=True)  # set verify to False if ssl cert is self-signed
    return content


def post_request(tags, finding_id):
    uri = os.getenv('POST_URL')  # path to api finding id + tags
    uri = f'{uri}{finding_id}/tags/'  # sum full path
    token = os.getenv('Token')  # your dd api token
    body = {"tags": tags}
    headers = {'content-type': 'application/json', 'Authorization': token}
    requests.post(uri, headers=headers, verify=True, json=body)