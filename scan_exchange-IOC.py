#!/usr/bin/env python3
#
#

this_v = "0.8 2021-03-16"


# getting latest IOCs
# https://twitter.com/tanmayg/status/1369125158481399809
#
# more DFIR-ressources/Links:
#
# https://zero.bs/sb-2107-emergency-patches-for-ms-exchange-hafnium-targeting-exchange-servers-with-0-day-exploits-cve-2021-26855.html#references



import requests 
import time 
import shutil
import yaml 
import os
import sys

import urllib3
urllib3.disable_warnings()


latest_iocs = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/MSTICIoCs-ExchangeServerVulnerabilitiesDisclosedMarch2021.json"


ioc_ts = int(time.time())

# files
current_iocs = "current_iocs.%s.json" % ioc_ts
yaml_file = "scan_exchange_ioc-%s.yaml" % ioc_ts
yaml_current = "scan_exchange_ioc-current.yaml" 
private_ioc_file = "private.iocs"
repo_link = "https://github.com/zer010bs/exchange-ioc-scan"
local_ioc_file = "local.iocs"

# known locations to iterate over for private.iocs


known_locations = [
  "owa/auth",
  "aspnet_client", 
  

]

def usage():
  print ("""

HELP: GOTO %s
  
  """ % repo_link)
  sys.exit()
  

print("""
                                ____________
                               /            \\
                              /  __________  \\
                             /  /        _/\  \\
                            |  /       _/   \  |
                            | |      _/      | |
                            | |     |        | |
                            | |     |        | |
 Exchange-Backdoor-Scan     | |     | O      | |
  CVE-2021-26855            | |     | .      | |
  IOCs by MS                | |     |        | |
                            | |     |        | |
  (c) 2021 zeroBS           | |     |        | |
      https://zero.bs       | |     |        | |
                            | |     |___     | |
                            | |         \____| |
                    -----------------------------------

    version : %s

""" % (this_v))

if len(sys.argv) > 1:
  usage()
  sys.exit()
  

#
#
# main
#
#

print("> loading public IOCs")

ioc_req = requests.get(latest_iocs, verify = False)


# will safe file later only if new IOCs found

ioc_json = ioc_req.json()

public_iocs = []
private_iocs = []
local_iocs = []


for ioc in ioc_json:
  if ioc["IndicatorType"] == "filepath":
   if ioc["Indicator"].find("""HttpProxy\\owa\\""") > -1:
     docroot_path = ioc["Indicator"].split("""HttpProxy\\""")[1].replace("\\", "/")
     public_iocs.append(docroot_path) 
   elif ioc["Indicator"].find("""C:\\inetpub\\wwwroot\\""") > -1:
     docroot_path = ioc["Indicator"].split("""wwwroot\\""")[1].replace("\\", "/")
     public_iocs.append(docroot_path)

# check for private iocs / check if new iocs available

if not os.path.isfile(private_ioc_file):
  # check if a scanfile exists, compare with IOCs from MS
  
  if os.path.isfile(yaml_current):
    with open(yaml_current, "r") as yc:
      loaded_iocs = yaml.load(yc, Loader=yaml.FullLoader)
      loaded_ioc_len = len(loaded_iocs["requests"][0]["path"])
  else:
    loaded_ioc_len = 0
  
  curr_ioc_len = len(public_iocs)
  
  if curr_ioc_len == loaded_ioc_len:
    print("no new IOCs to load, not writing a new scan_yaml")
    sys.exit()
  else:
    print("""
  
  > new IOCs  : %s
  > old IOCs  : %s  
    
  """ % (curr_ioc_len, loaded_ioc_len))

else:
  print("> loading private IOCs")
  with open(private_ioc_file, "r") as pi:
    for line in pi:
      line = line.strip()
      if len(line) > 1:
        if line[0] == "#": # we can haz comments
          continue
      else:
        continue 
      for kl in known_locations:
        kl_path = "%s/%s" % (kl, line)
        if kl_path in public_iocs:
          # ~ pass
          print("  > skipping %s, already in public IOCs" % (line))
        else:
          private_iocs.append(kl_path)

if os.path.isfile(local_ioc_file):
  print("> loading local IOCs")
  with open(local_ioc_file, "r") as li:
    for line in li:
      line = line.strip()
      if len(line) > 1:
        if line[0] == "#": # we can haz comments
          continue
      else:
        continue 
      for kl in known_locations:
        kl_path = "%s/%s" % (kl, line)
        if kl_path in public_iocs:
          print("  > skipping %s, already in public IOCs" % (line))
        else:
          local_iocs.append(kl_path)


print("""

loaded IOCs to write to scanfile

public  : %s
private : %s
local   : %s

""" %  (len(public_iocs), len(private_iocs), len(local_iocs)))


# saving curr_IOCs 
with open(current_iocs, "w") as cioc:
  cioc.write(ioc_req.text)



nuclei_yaml_txt_header = """
id: CVE-2021-26855

info:
  name: CVE-2021-26855-IOC-Scan
  author: zeroBS 
  severity: critical
  reference: 
    - https://twitter.com/tanmayg/status/1369125158481399809
    - https://twitter.com/zero_B_S/status/1369289560493064192
  tags: exploits, exchange, ioc

requests:
  - method: GET
    path:
"""

nuclei_yaml_txt_footer = """
    matchers:
      - type: status
        status:
          - 200
"""


with open(yaml_file, "w") as yf:
  yf.write(nuclei_yaml_txt_header)
  for ioc in public_iocs:
    yf.write("""      - "{{BaseURL}}/%s" \n""" % ioc)
  if len(local_iocs) > 0:
    yf.write("""      # local (but yet public) IOCs \n""" )
    for ioc in local_iocs:
      ioc = ioc.strip()
      if ioc[0] == "#":
        # this is a comment
        continue
      yf.write("""      - "{{BaseURL}}/%s" \n""" % ioc)
  if len(private_iocs) > 0:
    yf.write("""      # private IOCs \n""" )
    for ioc in private_iocs:
      ioc = ioc.strip()
      if ioc[0] == "#":
        # this is a comment
        continue
      yf.write("""      - "{{BaseURL}}/%s" \n""" % ioc)
    
  yf.write(nuclei_yaml_txt_footer)

print("""

> wrote [ %s ] Webshell/IOCs to %s

> happy hunting

""" % (( len(public_iocs) + len(private_iocs) + len(local_iocs)), yaml_current))

shutil.copyfile(yaml_file, yaml_current)
