import requests as req
from bs4 import BeautifulSoup
import re


proxies = {
   'https': 'http://<ip-address>:<port>',  # your proxy
}


def connection(uri):    # Tenable connection
    if "vpr_score" in uri:
        try:
            resp = req.get(uri, proxies=proxies)
        except req.exceptions.ConnectionError:
            req.status_code = "Connection refused"
    else:
        resp = req.get(uri, proxies=proxies)
    soup = BeautifulSoup(resp.text, 'lxml')
    return soup


# Parsing search plugins page
def tenable_serf(url):
    soup = connection(url)
    content = soup.find_all("a", {"class": "no-break"})
    if len(content) > 0:
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
            if "Risk" in content and "Risk" not in data.keys():
                xr = content.split()
                data[xr[0]] = xr[2]

            # Uncomment code below if you need parse Score value
            # if "Score" in content and "Score" not in data.keys():
            #     xs = content.split(':')
            #     data[xs[0]] = xs[1]

            if "Exploit Available" in content and "Exploit Available" not in data.keys():
                xv = content.split(':')
                data[xv[0]] = xv[1]
        return data
