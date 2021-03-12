#!/usr/bin/env python
#
# script to generate URLs from IP_LIST or IP|PORT - list as input to 
# nuclei
# 
# execute:
# ./nucular.py your_ip.list | nuclei -v -t [template_file] -o [output]
#

import sys

ip_file = sys.argv[1]

urls = {}

with open(ip_file, "r") as checkme:
  for line in checkme:
    #~ print(line)
    line = line.strip()
    try:
      x = line.split("|")
      ip = x[0]
      port = x[1]
    except:
      ip = line
      port = None
    if not port:
      url = "https://%s" % (ip)
      urls[url] = url
      url = "http://%s" % (ip)      
      urls[url] = url      
    else:
      if port == "80":
        url = "http://%s" % ip
      elif port ==  "443":
        url = "https://%s" % ip 
      else:
        url = "https://%s:%s" % (ip, port)
        urls[url] = url
        url = "http://%s:%s" % (ip, port)      
      urls[url] = url

for url in urls:
  print(url.strip())
