import requests
import warnings
import time
from RUCKUS_API_calls import SZ_API_calls

SmartZone = SZ_API_calls()

host = "10.0.0.98"
szUser = "admin"
szPassword = "ruckus123!"
zone = "Solar System"
wlan = "europa"
clientMac = "38:53:9C:94:70:9F"
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def main():
	n = 0
	token = SmartZone.getToken(host, szUser, szPassword)
	zoneId = SmartZone.getZoneID(host, zone, token)
	wlanId = SmartZone.getWlanID(host, zoneId, wlan, token)
	print ('{:<8s} {:<20s}'.format("token: ", token))
	print ('{:<8s} {:<20s}'.format("zoneId: ", zoneId))
	print ('{:<8s} {:<20s}'.format("wlanId: ", wlanId))
	print ()
	print ('{:<10s} {:<10s} {:<12s} {:<10s} {:<10s} {:<10s} {:<10s} {:<10s}'.format("uplink", "downlink","traffic","txFrames","rxFrames", "uplinkRate","downlinkRate","txRatebps"))

	while True:
		response = SmartZone.getWlanTrafficByClient(host, zoneId, wlanId, clientMac, token)
		clientTraffic = response.json()
		#print (clientTraffic)
		print ('{:<10s} {:<10s} {:<12s} {:<10s} {:<10s} {:<10s} {:<12s} {:<10s}'.format(str(clientTraffic['list'][0]['uplink']), str(clientTraffic['list'][0]['downlink']),str(clientTraffic['list'][0]['traffic']),str(clientTraffic['list'][0]['txFrames']),str(clientTraffic['list'][0]['rxFrames']), str(clientTraffic['list'][0]['uplinkRate']),str(clientTraffic['list'][0]['downlinkRate']),str(clientTraffic['list'][0]['txRatebps'])))
		n = n + 1
		if n == 12:
			print ('{:<10s} {:<10s} {:<12s} {:<10s} {:<10s} {:<10s} {:<10s} {:<10s}'.format("uplink", "downlink","traffic","txFrames","rxFrames", "uplinkRate","downlinkRate","txRatebps"))
			n = 0
		time.sleep(5)

if __name__ == "__main__":
	main()