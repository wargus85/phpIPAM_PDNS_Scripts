#!/usr/bin/env python3

import requests, argparse, getpass, sys, urllib3
from datetime import date

import urllib.parse
#disable insecure warning from requests, this does not stop https/tls requests, but simply wont check the certificate.
urllib3.disable_warnings()

# get some variables
parser = argparse.ArgumentParser(description="Script to get (and set) the next available IP address in a subnet from IPAM. It can optionally take a second subnet ID for IPv6 allocation")
parser.add_argument("--username","-u", type=str,help="DCIM Username",required=True)
parser.add_argument("--subnet","-s", type=str,help="Subnet ID (int) to request address in",required=True)
parser.add_argument("--password",'-p',type=str,help="DCIM Password'",required=False)
parser.add_argument("--apiid","-a", type=str,help="API Application ID for PHPipam",required=True)
parser.add_argument("--pdnsapi","-d",type=str,help="PowerDNS API Key",required=True)
parser.add_argument("--hostname","-n",type=str,help="FQDN of the host",required=True)
parser.add_argument("--v6","-6",type=int,help="if requesting secondary IPv6 address, provide the subnet ID",required=False)
args = parser.parse_args()


# You will need to set these to your PowerDNSAdmin and phpIPAM urls 
BASE_URL = "https://your_ipam_url.com/api/"+args.apiid+"/"
PDNS_BASE_URL = "https://powerdns.yourdom.com/" + "api/v1/servers/localhost/zones/YOURZONE.com"

#get the date
today = date.today()

# Setup the password
if args.password is None:
    PASSWORD = getpass.getpass(prompt='Enter your AD password: ')
else: 
    PASSWORD = args.password

# Define the username
USER = args.username


# function to get the Token for all the other API calls, needs to run once.
def getToken(username,password,URL):

    TokenResponse = requests.post(URL+"user/",auth=(username,password),verify=False)
    if 200 <= TokenResponse.status_code >= 299:
        print(str(TokenResponse.status_code)+" "+TokenResponse.reason)
        sys.exit(1)
    else:
        return TokenResponse.json()['data']['token']

# Define a function to set the IP address
def SetIPAddr(subnetID,token,hostname,base_url):

    headers = {'token':token}
    payload = {'hostname':hostname,'description':'created '+str(today)+" by "+args.username}
    response = requests.post(base_url+"addresses/first_free/"+str(subnetID),headers=headers,verify=False,json=payload)
    if 200 <= response.status_code >= 299:
        print('bad request:'+str(response.status_code))
        sys.exit(2)
    reserved_addr = response.json()['data']
    return reserved_addr

# Function that sets the IPv4 Address in PDNSAdmin
def UpdateIPv4DNS(APIKey,hostname,IPv4Address,BASE_URL):
    headers = {'X-API-Key': APIKey, 'Content-Type':'application/json'}
    payload = {"rrsets": [ {"name": hostname+'.', "type": "A", "ttl": "60", "changetype": "REPLACE", "records": [ {"content":IPv4Address,"disabled": False } ] } ]}
    DNSUpdate = requests.patch(BASE_URL,json=payload,verify=False,headers=headers)
    if 200 <= DNSUpdate.status_code >= 299:
        print('bad request:'+str(DNSUpdate.status_code))
        return False
    return True

# Function that sets the IPv6 Address in PDNSAdmin
def UpdateIPv6DNS(APIKey,hostname,IPv6Address,BASE_URL):
    headers = {'X-API-Key': APIKey, 'Content-Type':'application/json'}
    payload = {"rrsets": [ {"name": hostname+'.', "type": "AAAA", "ttl": "60", "changetype": "REPLACE", "records": [ {"content":IPv6Address,"disabled": False } ] } ]}
    DNSUpdate = requests.patch(BASE_URL,json=payload,verify=False,headers=headers)
    if 200 <= DNSUpdate.status_code >= 299:
        print('bad request:'+str(DNSUpdate.status_code))
        return False
    return True


# Setup the token for PHPIpam
token = getToken(USER,PASSWORD,BASE_URL)

#Always set an IPv4 Address in IPAM and DNS
IPv4Address = SetIPAddr(args.subnet,token,args.hostname,BASE_URL)
print(str(IPv4Address))
IPv4Success = UpdateIPv4DNS(args.pdnsapi,args.hostname,IPv4Address,PDNS_BASE_URL)
if IPv4Success == False:
    print("unable to set IPv4 DNS Address")
    sys.exit(3)

# Run this is we want to also set the Ipv6 address
if args.v6 is not None:
    IPv6Address = SetIPAddr(args.v6,token,args.hostname,BASE_URL)
    print(str(IPv6Address))
    IPv6Success = UpdateIPv6DNS(args.pdnsapi,args.hostname,IPv6Address,PDNS_BASE_URL)
    if IPv6Success == False:
        print("unable to set IPv6 DNS Address")
        sys.exit(4)