host = "10.0.0.205"
username = "admin"
password = "password"
numberOfZones = 5
requiredSoftware = '5.2.0.0.1412'
zoneIdList = []
zoneNameList = []

from RUCKUS_API_calls import SZ_API_calls
SmartZone = SZ_API_calls()

def main():
	token = SmartZone.getToken(host, username, password)
	zones = SmartZone.getZones(host, token)
	for zone in zones['list']:
		if zone['name'] != 'Staging Zone' and zone['name'] != 'Default Zone':
			zoneDetails = SmartZone.queryZone(host, zone['id'], token)
			print (zone['id'],zone['name'])
			print (zoneDetails['version'])
			if zoneDetails['version'] != requiredSoftware and len(zoneIdList) < numberOfZones:
				zoneIdList.append(zone['id'])
				zoneNameList.append(zone['name'])

	if len(zoneNameList) > 0:
		print (zoneNameList)
		yesNo = input("Do you want to upgrade the listed zones? (Yes/No):")
		if yesNo == 'Yes' or yesNo == "Y" or yesNo == "y":
			if len(zoneIdList) > numberOfZones:
				size = numberOfZones
			else:
				size = len(zoneIdList)
			for i in range (0, size):
				r = SmartZone.upgradeZoneFirmware(host,zoneIdList[i],requiredSoftware,token)
				if "204" in str(r) :
					print (zoneNameList[i] + " - Success")
	else:
		print ("There are no zones to be upgraded")

if __name__ == "__main__":
	main()