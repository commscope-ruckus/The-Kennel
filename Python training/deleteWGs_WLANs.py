host = '10.0.0.98'
username = 'admin'
password = 'password'
zone = 'Saturn'
wlanPassphrase = 'password'
vlanID = 1

from RUCKUS_API_calls import SZ_API_calls
SmartZone = SZ_API_calls()

def main():
	token = SmartZone.getToken(host, username, password)
	zoneID = SmartZone.getZoneID(host, zone, token)
	for i in range (0, 5):	
		wlanGroupName = "wg" + str(i)
		wlanGroupID = SmartZone.getWlanGroupID(host, zoneID, wlanGroupName, token)
		r = SmartZone.deleteWlanGroup(host, zoneID, wlanGroupID, token)
		wlanName = "wlan" + str(i)
		wlanID = SmartZone.getWlanID(host, zoneID, wlanName, token)
		r = SmartZone.deleteWlan(host, zoneID, wlanID, token)
		print (r)

if __name__ == "__main__":
	main()