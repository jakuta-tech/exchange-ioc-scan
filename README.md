
# Readme

a script to generate a YAML-Scan-file (nuclei-template) for 
[nuclei-scanner](https://github.com/projectdiscovery/nuclei) 
based on [IOCs released by Microsoft](https://twitter.com/tanmayg/status/1369125158481399809)
and local.iocs (public as well, see comments in the file) 
from various sources on observed Webshells.

you can add your private.iocs if necessary (see below)


![exe-cute](exe-cute.png)



the scanfile will detect implanted webshells, if known so far as IOC, or given as
private IOCs, and can update the scanfile if new IOCs are found


workflow is as follows:

- Download a internet-wide search for OWA-hosts

- generate a current nuclei-template-file with `scan_exchange-IOC.py`:
    - this willdownload the current IOC-json from Micrsosoft
    - then generate nuclei-template file called `scan_exchange_ioc-current.yaml` (a backup is safed on each run in `scan_exchange_ioc-$TIMESTAMP.yaml`

- scan your hosts with nuclei and your template 
- if you want to check for new IOCs later, just re_run `scan_exchange-IOC.py` ; if there a new IOCs to be found, a new `scan_exchange_ioc-current.yaml`
  file is generated; if no new IOCs, the script will exit
  

using private IOCs additionally:
- place a file called "private.iocs" into this directory
- put one webshell.aspx on each line; if the path does not contain a "/",  pathes will get expanded to well-known locations, e.g.
    - {{BaseURL}}/aspnet_client/webshell.aspx
    - {{BaseURL}}/owa/auth/webshell.aspx
- if the path contains a "/" liek owa/auth/yourprivatewebshell.aspx, this path will be taken as path beneath `{{BaseURL}}`

- check your `scan_exchange_ioc-current.yaml` - in the section below comment 
  # private_iocs
- please not: a check for new IOCs online will be skipped (as of v0.4), thus each time a new scan_template is generated 


example:

~~~
# private.iocs

shellA.aspx
ShellB.aspx
DssQQ21.aspx

~~~
  

scan in action:

![scan in action](scanning.png)

# Backdoor-Outputs and reducing FP in the dataset

- based on [cisa-iocs](https://us-cert.cisa.gov/ncas/current-activity/2021/03/13/updates-microsoft-exchange-server-vulnerabilities)
  and an own analysis looking a  a njumber of outputs from the first bdatase with 110k hits  and far too many FP
  we identified 3 different backdoor-outputs 


## MOAB/ChinaChoppper

- found very often
- [cisa-iocs](https://us-cert.cisa.gov/ncas/current-activity/2021/03/13/updates-microsoft-exchange-server-vulnerabilities)
- looks like

~~~
> GET /aspnet_client/shell.aspx HTTP/1.1
> Host: XXXXXX
> User-Agent: XXXXX
> Accept: */*
> 
< HTTP/1.1 200 OK
< Cache-Control: private
< Content-Type: text/html; charset=utf-8
< Server: Microsoft-IIS/8.5
< X-AspNet-Version: 4.0.30319
< Date: Mon, 22 Mar 2021 14:45:10 GMT
< Content-Length: 2126
< 
Name                            : OAB (Default Web Site)
PollInterval                    : 480
OfflineAddressBooks             : 
RequireSSL                      : True
BasicAuthentication             : False
WindowsAuthentication           : True
OAuthAuthentication             : False
MetabasePath                    : IIS://[REDACTED]/W3SVC/1/ROOT/OAB
Path                            : C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\OAB
ExtendedProtectionTokenChecking : None
ExtendedProtectionFlags         : 
ExtendedProtectionSPNList       : 
AdminDisplayVersion             : Version 15.1 (Build 2106.2)
Server                          : [REDACTED]
InternalUrl                     : https://[REDACTED]/OAB
InternalAuthenticationMethods   : WindowsIntegrated
ExternalUrl                     : http://f/
ExternalAuthenticationMethods   : WindowsIntegrated
AdminDisplayName                : 
ExchangeVersion                 : 0.10 (14.0.100.0)
DistinguishedName               : CN=OAB (Default Web Site),CN=HTTP,CN=Protocols,CN=[REDACTED]L,CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=R[REDACTED],CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=[REDACTED],DC=net
Identity                        : [REDACTED]\OAB (Default Web Site)
Guid                            : 1ead5594-759f-4966-9b96-98db7b0a34dd
ObjectCategory                  : [REDACTED]/Configuration/Schema/ms-Exch-OAB-Virtual-Directory
ObjectClass                     : top
                                  msExchVirtualDirectory
                                  msExchOABVirtualDirectory
WhenChanged                     : 3/4/2021 8:07:21 AM
WhenCreated                     : 3/3/2021 6:17:56 PM
WhenChangedUTC                  : 3/4/2021 4:07:21 PM
WhenCreatedUTC                  : 3/4/2021 2:17:56 AM
OrganizationId                  : 
Id                              : [REDACTED]\OAB (Default Web Site)
OriginatingServer               : [REDACTED].net
IsValid                         : True

~~~

# Whitelist-Consideration





# Changelog

v0.9 - 2021-03-28
  - outlook_CountryCode.aspx - modification

v0.8 - 2021-03-22
  - comparing ioc-list with a whitelist, see whitelist-considerations
  - getting some smoking guns for various backdoors included as well, reducing FP
  


v0.7 2021-03-17
  - added local.iocs from https://us-cert.cisa.gov/ncas/current-activity/2021/03/13/updates-microsoft-exchange-server-vulnerabilities
  

v0.6 2021-03-15
  - added new known_locations based on CISA-IOCs
  - added cisa.iocs
  - you can have commens in ioc - files 
  

v0.4 2021-03-12 
  - generate new scan_file only if new IOCs found
  - use private IOCs for private scans (skipping the check for new IOCs)
  

v0.2 2021-03-10 
  - first hackish version
  - first bugs fixed
