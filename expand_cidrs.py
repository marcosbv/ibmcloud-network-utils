import ipaddress
import sys
import os

fileName=sys.argv[1]
file=open(fileName)

cidrArr=file.read().split('\n')

for i in cidrArr:
   if i == '':
      continue
   cidr=ipaddress.ip_network(i)
   for ip in cidr:
      print(ip)
