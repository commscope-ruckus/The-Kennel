
import csv
import requests
import json
import sys
import uuid
from datetime import datetime

CPFQDN = "cloudpath.my.domain" # Cloudpath FQDN or ip address
CPUSER = "your Cloudpath admin username/email" # Cloudpath user name/email
CPPASSWORD = "password" # Cloudpath password
SZKEYFILE = "nameofyourdpskexportfile.csv" # .csv file with DPSKs exported from SZ (Clients/Dynamic PSK/Export All)
CPDPSKGUID = "yourDPSKpoolGuid" # Cloudpath DPSK Pool Guid (Configuration/DPSK Pools)

# run using python3 SZtoCPDPSKv9r.py

def readfile():
    dateTimeObj = datetime.now()
    timestampStr = dateTimeObj.strftime("%m-%d-%Y")
    print ("Reading CSV file", end = "")
    with open(SZKEYFILE, mode="r", encoding="utf-8-sig") as csv_file:
        reader = csv.DictReader(csv_file)
        result = {}
        for row in reader:
            key = row.pop("Passphrase")
            result[key] = row
            row["uuid"] = "SZ2CP-"+timestampStr+"-"+str(uuid.uuid4())
            print (".", end = "")
    print (" ")
    return result

def getcptoken(username, password):
    #print ("Getting API token")
    url = "https://"+CPFQDN+"/admin/publicApi/token"
    body = {"userName":username, "password":password}
    response = requests.post(url, json=body)
    token = response.json()['token']
    return token

def createdpsks(olddpsk):
    url = "https://"+CPFQDN+"/admin/publicApi/dpskPools/"+CPDPSKGUID+"/dpsks"
    for key in olddpsk:
        token = getcptoken(CPUSER, CPPASSWORD)
        print ('Creating EDPSK '+key+" ", end = "")
        uuid = olddpsk[key]["uuid"]
        VLAN = olddpsk[key]["VLAN ID"]
        name = olddpsk[key]["User Name"]
        cpheaders = {"Content-Type":"application/json", "Authorization":token}
        body = {"name":uuid, "passphrase":key, "vlanid":VLAN, "thirdPartyId":name}
        response = requests.post(url, headers=cpheaders, json=body)
        print (response)
    print (" ")
    return

def main(argv):
    szkeys = readfile()
    createdpsks (szkeys)
    return

if __name__ == "__main__":
        main(sys.argv[1:])
