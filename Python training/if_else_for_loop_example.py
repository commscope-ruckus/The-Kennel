import requests
import warnings

HOST = "10.0.0.205"
SZUSER = "admin"
SZPASSWORD = "password"
requiredSoftware = '5.2.2.0.301'
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# get the authorization token
url = "https://" + HOST + ":8443" + "/wsg/api/public/v9_0/serviceTicket"
body = {'username': SZUSER,'password': SZPASSWORD}
response = requests.post(url, json = body, verify=False)
token = response.json()['serviceTicket']
print (token)

# get the zones
url = "https://" + HOST + ":8443" + "/wsg/api/public/v9_0/rkszones?serviceTicket=" + token
response = requests.get(url, verify=False)
zones = response.json()
print (zones)

# verify the software in each zone, except the Staging Zone and Default Zone
for zone in zones['list']:
	if zone['name'] != 'Staging Zone' and zone['name'] != 'Default Zone':
		url = "https://" + HOST + ":8443" + "/wsg/api/public/v9_0/rkszones/" + zone['id'] + "?serviceTicket=" + token
		response = requests.get(url, verify=False)
		zoneDetails = response.json()
		if zoneDetails['version'] != requiredSoftware:
			print ("need to upgrade software in zone " + zone['name'])
		else:
			print ("zone " + zone['name'] + " has the correct software")