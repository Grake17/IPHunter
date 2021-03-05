#=======================================================================================================================
# Scan IP
#=======================================================================================================================

import urllib3
import json
import  requests

def whoistest(ip):

    try:
        # IpWhoIS
        http = urllib3.PoolManager()
        url = "http://ipwhois.app/json/"+ip
        r = http.request('GET', url)
        response = json.loads(r.data)

        # AbuseIpDB
        url2 = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': '1dfac7af7a7b0e8a8dc12a1c7a97c957a4ce8f23f41c9ace9a28c6b1cba3ec57a9ebb40668396336'
        }

        response2 = requests.request(method='GET', url=url2, headers=headers, params=querystring)

        # Formatted output
        decodedResponse = json.loads(response2.text)
        test = decodedResponse["data"]
        return response,test

    except:
        conn = "error on connection"
        return conn
