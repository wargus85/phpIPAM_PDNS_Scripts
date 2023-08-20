# phpIPAM and PowerDNS API Scripts

This repo contains two scripts:
* set_ip_addresses.py, and
* rm_ip_addresses.py.

Fundamentally the scripts will update a hostname and IP addresses in both phpIPAM and PowerDNSAdmin, and also remove them. In my setup, phpIPAM talks directly to the PDNS database to make changes to records. However, the API in phpIPAM does not allow for the creation of DNS records and as such I take advantage of the PDNS Admin API - as distinct from the PDNS API. PDNS Admin can have multiple API Keys, which is useful for auditing purposes, whereas PDNS itself only has the one, which PDNSAdmin takes advantage of.

#### Useful URLs:
* https://phpipam.net/api-documentation/
* https://github.com/PowerDNS-Admin/PowerDNS-Admin/blob/master/docs/API.md
* https://doc.powerdns.com/md/httpapi/api_spec/

### Gotchas

As my phpIPAM is hosted by Apache, I had to configure the following in the site configuration to get the API working. I was getting 404 errors despite following the documentation and using their curl examples.

```xml
<Directory /path/to/phpipam/ >
    Options FollowSymLinks
    AllowOverride all
    Order allow,deny
    Allow from all
</Directory>
```


### set_ip_address does the following:
```
usage: set_ip_address.py [-h] --username USERNAME --subnet SUBNET [--password PASSWORD] --apiid APIID --pdnsapi PDNSAPI --hostname HOSTNAME [--v6 V6]

Script to get (and set) the next available IP address in a subnet from IPAM. It can optionally take a second subnet ID for IPv6 allocation

options:
  -h, --help            show this help message and exit
  --username USERNAME, -u USERNAME
                        DCIM Username
  --subnet SUBNET, -s SUBNET
                        Subnet ID (int) to request address in
  --password PASSWORD, -p PASSWORD
                        DCIM Password'
  --apiid APIID, -a APIID
                        API Application ID for PHPipam
  --pdnsapi PDNSAPI, -d PDNSAPI
                        PowerDNS API Key
  --hostname HOSTNAME, -n HOSTNAME
                        FQDN of the host
  --v6 V6, -6 V6        if requesting secondary IPv6 address, provide the subnet ID
```
### rm_ip_addresses.py does the following:
```
usage: rm_ip_address.py [-h] --username USERNAME [--password PASSWORD] --apiid APIID --hostname HOSTNAME

Script to remove the IPv6 and IPv4 addresses and DNS records from IPAM and PowerDNS Admin

options:
  -h, --help            show this help message and exit
  --username USERNAME, -u USERNAME
                        DCIM Username
  --password PASSWORD, -p PASSWORD
                        DCIM Password'
  --apiid APIID, -a APIID
                        API Application ID for PHPipam
  --hostname HOSTNAME, -n HOSTNAME
                        FQDN of the host
```

## Requirements

First and foremost, you'll need to have phpIPAM, PowerDNS and PowerDNS Admin up and running. How you do that is up to you.

The scripts assume that you have the same username and password for both phpIPAM and PowerDNS. This is the case in my environment with both applications using Active Directory/Keycloak SSO for authentication and authorization.

### API Keys
You'll need to setup the API Keys in both Power DNS Admin and phpIPAM. You'll need to know the API Key from PowerDNS Admin and the 'App ID' from phpIPAM, in my setup, I have the App Security setting for the API in phpIPAM set to 'SSL with User token'.

For PowerDNS Admin - which I have running in a docker container, also reverse proxying behind Apache - no modifications or changes were required. The API worked immediately. The API Key has 'Operator' priviliges, which seem to be enough to do the job.

## Getting Started
You'll need to install requests and urllib3 into your python3 environment. These scripts were written on Ubuntu 22 using Python 3.10, so you may need to modify the scripts to suit your Python version.

In the scripts themselves, you'll need to set the URLs to point to your instances of PowerDNS Admin and phpIPAM. You will also need to add your zone. In my environment I only have one zone, currently the scripts do not work with multiple zones, but could be easily modified to do that.


## Usage
Once you've done the necessary setup, running the scripts is straight forward.

Create a new host with an IPv4 and IPv6 address, updating the DNS records:
```bash
./set_ip_address.py -6 29 -s 21 -u your_username -a phphIPAMApp_ID -d YoUrApIKeYH3r3 -n "example.yourdom.net"
Enter your AD password: ********
172.16.21.5
2513:450f:71:4::e
```
In the above example, my ipv4 subnet ID is 21, and the IPv6 subnet ID is 29.

Delete the above:
```bash
./rm_ip_address.py -u your_username -a phphIPAMApp_ID -n "example.yourdom.net"
Enter your AD password: 
deleting example.yourdom.net IP: 172.16.21.5
deleting example.yourdom.net IP: 2513:450f:71:4::e and deleting hostname
```

In both cases above, the password can be provided in clear text and passed to the script. This is useful for automation in Ansible etc.

## The Future

Currently the scripts do print out the IP addresses, but in the future I will adjust that to be more scripting friendly. So for instance I plan make it possible for ansible to retrieve the addresses and use them in provisioning new VMs in my libvirt/cloud-init environments.