import csv
import requests
import sys
from RUCKUS_API_calls import CP_API_calls

host = "10.0.0.239"
username = "marcelo@commscope.com"
password = "password"
cpApiKey = "apikey"
szDPSKfile = "dpsk_20210621073458.csv"
cpDPSKpoolGuid = "AccountDpskPool-f734697a-21e9-4b87-a375-5963497e3686"

Cloudpath = CP_API_calls()

def readfile(szDPSKfile):
	print ("Reading CSV file...")
	reader = csv.DictReader(open(szDPSKfile))
	result = {}
	for row in reader:
		key = row.pop('\ufeff"User Name"')
		if key in result:
			print(key + ' is duplicated')
		result[key] = row
	return result

def main():
	r = Cloudpath.getToken(host, username, password, cpApiKey)
	token = r.json()['token']
	szkeys = readfile(szDPSKfile)
	for user in szkeys:
		passphrase = szkeys[user]['Passphrase']
		vlanID = szkeys[user]['VLAN ID']
		r = Cloudpath.createdpsks(host, user, passphrase, vlanID, cpApiKey, cpDPSKpoolGuid, token)
		if "201" in str(r):
			print ('Created DPSK for '+ user)
		elif "409" in str(r) :
			print ('DPSK for '+ user + ' already exists')
		else:
			print ('Could not create DPSK for '+ user)

if __name__ == "__main__":
	main()