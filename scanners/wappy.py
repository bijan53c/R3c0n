import requests
import json
file = open('targeturl.txt','r')
readfile = file.read()
TargetURL = readfile.strip()
print ("target : ",TargetURL)
url = 'https://api.wappalyzer.com/v2/lookup/?urls=' + TargetURL 
headers = {'x-api-key' : '<wapplyzer API key>'}
r = requests.get(url, headers=headers)
response_file = r.json()
clean_response = json.dumps(response_file,sort_keys=True, indent=4)
print(clean_response)
resultfile = open('wappyresult.txt','w')
resultfile.write(clean_response)
file.close()
resultfile.close()
