import requests as req
from bs4 import BeautifulSoup
import re


def connection(uri):    # Tenable connection
    if "vpr_score" in uri:
        resp = req.get(uri)
    else:
        resp = req.get(uri)
    soup = BeautifulSoup(resp.text, 'lxml')
    return soup


# Parsing search plugins page
def tenable_serf(url):
    soup = connection(url)
    content = soup.find_all("a", {"class": "no-break"})
    ident = str(content[0])
    ident = ident.split('"')
    uri = ident[3]
    return uri


# Parsing plugins info
def www(uri):
    data = {}
    soup = connection(uri)

    # check containing VPR in content
    strings = soup.find_all(string=re.compile('VPR')) or soup.find_all(string=re.compile('Exploit Available'))
    if len(strings) > 0:
        for tag in soup.find_all("p"):
            content = tag.text
            if "Risk Factor" in content and "Risk Factor" not in data.keys():
                xr = content.split(':')
                data[xr[0]] = xr[1]
            if "Score" in content and "Score" not in data.keys():
                xs = content.split(':')
                data[xs[0]] = xs[1]
            if "Exploit Available" in content and "Exploit Available" not in data.keys():
                xv = content.split(':')
                data[xv[0]] = xv[1]
    data["References"] = uri
    return data
