import requests
import time
import json
import pandas

file_path = str(input('Enter File Path: '))
domain_CSV = pandas.read_csv((file_path))

Urls = domain_CSV['Domain'].tolist()

API_key = 'a6343fc0cf89304335352937d465b84e29c97bc2ecc82d43ec0bd16bfd27c2e5'
url = 'https://www.virustotal.com/vtapi/v2/url/report'

for i in Urls:
    parameters = {'apikey': API_key, 'resource': i}
    response = request.get(url=url, params=parameters)
    json_response= json.loads(response.text)
    if json_response['response'] <= 0:
        with open('Virustotal Clean results.txt', 'a') as clean:
            clean.write(i) and clean.write("\tNot Malicious\n")
    else:
        with open ('Virustotal Malicious result.txt', 'a') as malicious:
            malicious.write(1) and malicious.write("\t malicious \n")

    time.sleep(20)