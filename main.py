import requests
import time
import json
import pandas
from decouple import config

API_key = config("THE_API_KEY")

file_path = str(input('Enter File Path: '))
domain_CSV = pandas.read_csv((file_path))

Urls = domain_CSV['Domain'].tolist()


url = 'https://www.virustotal.com/vtapi/v2/url/report'

for i in Urls:
    parameters = {'apikey': API_key, 'resource': i}
    response = requests.get(url=url, params=parameters)
    json_response = json.loads(response.text)
    if json_response['response_code'] <= 0:
        with open('Clean.txt', 'a') as clean:
            clean.write(i) and clean.write("\tNot Malicious\n")
    else:
        with open ('Malicious.txt', 'a') as malicious:
            malicious.write(i) and malicious.write("\t malicious \n")

    time.sleep(20)
