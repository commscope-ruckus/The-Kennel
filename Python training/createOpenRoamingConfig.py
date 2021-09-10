from RUCKUS_API_calls import SZ_API_calls

host = "10.0.0.189"
username = "admin"
password = "password"
domain = 'California'
zone = "OpenRoaming Trial"
proxyAAAname = "GlobalReach RADsec AAA"
operatorName = "San Mateo County"
operatorFriendlyName = "San Mateo County"
identityProviderName = "GlobalReach"
zoneProfileName = "WBA OR profile"
homeOisName = "WBA OR RCOI"
wlanName = "OpenRoaming"
ssid = "OpenRoaming"
clientCertificateName = "GlobalReach Client Certificate"
trustCaCertificateName = "GlobalReach CA Chain Certificate"
proxyAAAipAddress = "<proxy ip address>"
realmName = "wballiance.com"
homeOis = "5a03ba0000"
operatorDomain = "bayarea.roamingid.net"
cnSanIdentity = "*.roamingid.net"
clientCertFile = "<certfile>"
privateKeyFile = "<privatekey>"
trustCaCertFile = "<certfile>"

SmartZone = SZ_API_calls()
 
def main():
	token = SmartZone.getToken(host, username, password)
	domainID = SmartZone.createDomain(host, domain, token)
	zoneID = SmartZone.createZone(host, domainID, zone, token)
	clientCertID = SmartZone.createClientCertificate(host, clientCertificateName, clientCertFile, privateKeyFile, token)
	trustCertID = SmartZone.createTrustCaCertificate(host, trustCaCertificateName, trustCaCertFile, token)
	RADsecProxyAAAid = SmartZone.createRADsecProxyAAA(host, domainID, proxyAAAname, cnSanIdentity, clientCertID, proxyAAAipAddress, token)
	operatorID = SmartZone.createWifiOperator(host, domainID, operatorName, operatorFriendlyName, operatorDomain, token)
	identityProviderID = SmartZone.createIdentityProvider(host, domainID, identityProviderName, realmName, homeOis, homeOisName, proxyAAAname, token)
	zoneProfileID = SmartZone.createHS20zoneProfile(host, zoneID, zoneProfileName, operatorID, identityProviderID, token)
	wlanID = SmartZone.createHS20wlan(host, zoneID, wlanName, ssid, zoneProfileID, token)
	print ('\n' + 'All OpenRoaming services were created - domain, zone, certificates, RadSec Proxy, operator, identity provider, zone profile and wlan' + '\n')

if __name__ == "__main__":
	main()