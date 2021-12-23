import requests
import json
file = open('targeturl.txt','r')
readfile = file.read()
TargetURL = readfile.strip()
url = "https://"+TargetURL
#targeturlHTTPS = "https://" + TargetURL
#targeturlHTTP = "http://" + TargetURL
print ("target : ",url)
url = 'https://api.wappalyzer.com/v2/lookup/?urls=' + url 
headers = {'x-api-key' : '<API key>'}
r = requests.get(url, headers=headers)
response_file = r.json()
clean_response = json.dumps(response_file,sort_keys=True, indent=4)
print(clean_response)
resultfile = open('wappyresult.txt','w')
resultfile.writelines(clean_response)
file.close()
resultfile.close()
