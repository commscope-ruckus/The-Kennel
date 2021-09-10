import requests
host = "ruckus.cloud"
username = "marcelo@ruckuswireless.com"
password = "password"

from RUCKUS_API_calls import RC_API_calls
RUCKUS_Cloud = RC_API_calls()

def main():
	s = requests.Session()
	r = RUCKUS_Cloud.getToken(s, host, username, password)
	print ("tenant ID: ", r['tenantId'], " API-KEY: ", r['API-KEY'] )
	guestUsers = RUCKUS_Cloud.getGuestUsers(s, host, r['tenantId'])
	for guestUser in guestUsers['content']:
		print ()
		print ('{:<8s} {:<20s}'.format("name: ", guestUser['name']))
		print ('{:<8s} {:<20s}'.format("email: ", guestUser['email']))
		print ('{:<8s} {:<20s}'.format("mobile: ", guestUser['mobilePhoneNumber']))
		print ('{:<8s} {:<20s}'.format("ssid: ", guestUser['ssid']))
	print ()

if __name__ == "__main__":
	main()