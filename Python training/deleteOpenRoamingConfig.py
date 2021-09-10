from RUCKUS_API_calls import SZ_API_calls

host = "10.0.0.189"
username = "admin"
password = "password"
domain = 'California'
zone = "OpenRoaming Trial"
proxyAAAname = "GlobalReach RADsec AAA"
operatorName = "San Mateo County"
identityProviderName = "GlobalReach"
zoneProfileName = "WBA OR profile"
wlanName = "OpenRoaming"
clientCertificateName = "GlobalReach Client Certificate"
trustCaCertificateName = "GlobalReach CA Chain Certificate"

SmartZone = SZ_API_calls()
 
def main():
	token = SmartZone.getToken(host, username, password)
	domainID = SmartZone.getDomainID(host, domain, token)
	zoneID = SmartZone.getZoneID(host, zone, token)
	wlanID = SmartZone.getWlanID(host, zoneID, wlanName, token)
	zoneProfileID = SmartZone.getHS20zoneProfileID(host, zoneID, zoneProfileName, token)
	identityProviderID = SmartZone.getIdentityProviderID(host, domainID, identityProviderName, token)
	operatorID = SmartZone.getWifiOperatorID(host, domainID, operatorName, token)
	RADsecProxyAAAid = SmartZone.getProxyAAAid(host, domainID, proxyAAAname, token)
	clientCertID = SmartZone.getClientCertID(host, clientCertificateName, token)
	trustCertID = SmartZone.getTrustCaCertID(host, trustCaCertificateName, token)
	SmartZone.deleteWLAN(host, zoneID, wlanID, token)
	SmartZone.deleteHS20zoneProfile(host, zoneID, zoneProfileID, token)
	SmartZone.deleteIdentityProvider(host, identityProviderID, token)
	SmartZone.deleteWifiOperator(host, operatorID, token)
	SmartZone.deleteProxyAAA(host, RADsecProxyAAAid, token)
	SmartZone.deleteClientCertificate(host, clientCertID, token)
	SmartZone.deleteTrustCaCertificate(host, trustCertID, token)
	SmartZone.deleteZone(host, zoneID, token)
	SmartZone.deleteDomain(host, domainID, token)
	print ('\n' + 'All OpenRoaming services were deleted - domain, zone, certificates, RadSec Proxy, operator, identity provider, zone profile and wlan' + '\n')

if __name__ == "__main__":
	main()