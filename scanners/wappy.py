import requests
import json
TargetURL = input ("Enter the URL: ")
url = 'https://api.wappalyzer.com/v2/lookup/?urls=' + TargetURL #+ '&sets=CMS'
headers = {'x-api-key' : '<wapplyzer API key>'}
r = requests.get(url, headers=headers)
response_file = r.json()
clean_response = json.dumps(response_file,sort_keys=True, indent=4)
print(clean_response)
