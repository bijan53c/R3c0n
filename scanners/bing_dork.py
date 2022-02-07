#V 07.02.2022
import urllib.request
from bs4 import BeautifulSoup

def bing (sit,page):
	url="https://www.bing.com/search?q=.site:"+site+"&go=&count=50&FORM=QBHL&qs=n&first="+str(page)

	hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0)' , "Accept-Language" : "en-us,en"}

	req = urllib.request.Request(url, headers=hdr,method="GET")

	response = urllib.request.urlopen(req)

	return response.read()

targetfile = open("targeturl.txt","r")
url = targetfile.read()
cleanURL = url.strip()
siteC = cleanURL #input("\n Target Domain:  ")
site = "."+siteC
page = "3"
print ("bing_dork.py - V_07.02.2022")
print (site)

print ()

f = open ("bingDORK_Result.txt","w")

list_subdomain = []

for i in range (int(page)):
	s = bing(site,i)
	soup = BeautifulSoup(s,'html.parser')

	for line in soup.find_all('a'):
		newline = line.get('href')

		if site in str(newline):
			n = "http://" if "http://" in newline else "https://"

			if n in newline:
				newline = newline.replace(n,"")
			new_1 = newline[0:newline.find("/")]
			if not new_1 in list_subdomain:
				list_subdomain.append(new_1)
				f.writelines(str(new_1)+"\n")
				print (new_1)
f.close()
