
import requests
from bs4 import BeautifulSoup

url = input("Enter The Website = ")

hdr = {"User-Agent" :"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
           "Cookie":"_ga=GA1.2.1814430428.1538172038; pushNotification-shownCount-9429=1; PHPSESSID=c1fa43e53a5d6a2f9f34d8cc96cd46af; _gid=GA1.2.2144402071.1611854335; tlc=true",
           "Accept-Language": "en-US,en;q=0.5",
           "Accept-Encoding":"gzip, deflate, br"}


links = []
l2 = []

def base_req(u):

    req = requests.get(url, headers=hdr)

    source = req.text

    return source


def base_crawl(s):

    filter_ = BeautifulSoup(s , "html.parser")

    for i in ("link","a","script"):

                for p in filter_.find_all(i):

                    p2 = p.get("href")
                    if p2 != None:
                        links.append(p2)


r = base_req(url)
base_crawl(r)

for i in links:

        try:
            if url+"/" == i or url == i:
                continue
            else:
                    print (i)
                    s = base_req(i)
                    base_crawl(s)
        except:
            pass

print ("links: \n")
for i in links:

        print (i)





