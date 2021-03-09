#!/usr/bin/env python3

import requests 
import time 
import shutil



# getting latest IOCs
# https://twitter.com/tanmayg/status/1369125158481399809
#
# more DFIR-ressources/Links:
#
# https://zero.bs/sb-2107-emergency-patches-for-ms-exchange-hafnium-targeting-exchange-servers-with-0-day-exploits-cve-2021-26855.html#references


latest_iocs = "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/MSTICIoCs-ExchangeServerVulnerabilitiesDisclosedMarch2021.json"


ioc_ts = int(time.time())
current_iocs = "current_iocs.%s.json" % ioc_ts


ioc_req = requests.get(latest_iocs, verify = False)

with open(current_iocs, "w") as cioc:
  cioc.write(ioc_req.text)

ioc_json = ioc_req.json()

filepath_ioc = []

for ioc in ioc_json:
  if ioc["IndicatorType"] == "filepath":
   if ioc["Indicator"].find("""HttpProxy\\owa\\""") > -1:
     docroot_path = ioc["Indicator"].split("""HttpProxy\\""")[1].replace("\\", "/")
     filepath_ioc.append(docroot_path)
   elif ioc["Indicator"].find("""C:\\inetpub\\wwwroot\\""") > -1:
     docroot_path = ioc["Indicator"].split("""wwwroot\\""")[1].replace("\\", "/")
     filepath_ioc.append(docroot_path)

     

# ~ print(filepath_ioc)


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

yaml_file = "scan_exchange_ioc-%s.yaml" % ioc_ts
yaml_current = "scan_exchange_ioc-current.yaml" 

with open(yaml_file, "w") as yf:
  yf.write(nuclei_yaml_txt_header)
  for ioc in filepath_ioc:
    yf.write("""      - "{{BaseURL}}/%s" \n""" % ioc)
  yf.write(nuclei_yaml_txt_footer)

print("""

> wrote [ %s ] Webshell/IOCs to %s

""" % (len(filepath_ioc), yaml_file))

shutil.copyfile(yaml_file, yaml_current)
