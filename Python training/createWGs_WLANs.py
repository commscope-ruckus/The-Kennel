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
	wlanGroupID = SmartZone.getWlanGroupID(host, zoneID, "default", token)
	defaultWG = wlanGroupID
	for i in range (0, 5):
		wlanGroupName = "wg" + str(i)
		wlanGroupID = SmartZone.createWlanGroup(host, zoneID, wlanGroupName, token)
		wlanName = "wlan" + str(i)
		ssid = "SSID" + str(i)
		passphrase = wlanPassphrase
		wlanID = SmartZone.createWlan(host, zoneID, wlanName, ssid, passphrase, token)
		r = SmartZone.addMemberToWlanGroup(host, zoneID, wlanGroupID, wlanID, vlanID, token)
		r = SmartZone.removeMemberFromWlanGroup(host, zoneID, defaultWG, wlanID, token)
		print ("WLAN group ID: ", wlanGroupID, " WLAN ID: ", wlanID)

if __name__ == "__main__":
	main()