#!/usr/bin/env python3

import requests, argparse, getpass, sys, urllib3

import urllib.parse
#disable insecure warning from requests, this does not stop https/tls requests, but simply wont check the certificate.
urllib3.disable_warnings()

# get some variables
parser = argparse.ArgumentParser(description="Script to remove the IPv6 and IPv4 addresses and DNS records from IPAM and PowerDNS Admin")
parser.add_argument("--username","-u", type=str,help="DCIM Username",required=True)
parser.add_argument("--password",'-p',type=str,help="DCIM Password'",required=False)
parser.add_argument("--apiid","-a", type=str,help="API Application ID for PHPipam",required=True)
parser.add_argument("--hostname","-n",type=str,help="FQDN of the host",required=True)
args = parser.parse_args()


# You will need to set these to your phpIPAM url 
BASE_URL = "https://your.ipam.here/api/"+args.apiid+"/"

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
        print("failed to get token")
        print(str(TokenResponse.status_code)+" "+TokenResponse.reason)
        sys.exit(1)
    else:
        return TokenResponse.json()['data']['token']

# Function to search for and return IP addresses given a hostname
def getIPaddresses(hostname,token,base_url):
    headers = {'token':token}
    addrReq = requests.get(base_url+"addresses/search_hostname/"+hostname,headers=headers,verify=False)
    if addrReq.status_code == 200:
        return addrReq.json()['data']
    else:
        print("failed to search for IP addresses")
        print('bad request:'+str(addrReq.status_code))
        sys.exit(2)

def deleteHost(HostID=int,base_url=str,delete=bool):
    headers = {'token':token}
    payload = {'remove_dns': '1'}
    if delete == True:
        requests.delete(base_url+"/addresses/"+str(HostID),headers=headers,verify=False,json=payload)
    else: 
        requests.delete(base_url+"/addresses/"+str(HostID),headers=headers,verify=False)

# Setup the token for PHPIpam
token = getToken(USER,PASSWORD,BASE_URL)

# Get the addresses from IPAM
Addresses = getIPaddresses(args.hostname,token,BASE_URL)

counter = 1
for i in Addresses:
    current = i  
    current['id']
    if Addresses.__len__() == counter:
        # Only delete all DNS entries on last call
        deleteHost(current['id'],BASE_URL,True)
        print("deleting "+current['hostname'] +" IP: "+current['ip']+" and deleting hostname")
    else:
        deleteHost(current['id'],BASE_URL,False)
        print("deleting "+current['hostname'] +" IP: "+current['ip'])
    counter = counter + 1