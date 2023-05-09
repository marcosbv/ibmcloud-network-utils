#################################################################################
# This small Python program receives a list of IPs and identifies which Security
# Groups cover that IP address. It uses IBM Cloud VPC SDK to retrieve a list of
# security group rules based on a naming pattern (partial security group name search) 
# and uses ipaddress Python library to check if the IP belongs to the CIDR.
#
# Environment Variables:
# IBMCLOUD_API_KEY (required): IBM Cloud API Key of an user with access to VPC infrastructure.
#
# Usage:
# python3 compare_ips_sg.py <security_group_partial_name> <region> <ips_file> <port> <direction(optional)>
# 
# Example:
# 
# python3 compare_ips_sg.py  "symphony-masters-" us-south ~/ip2.txt 9101
#   Check for security groups rules that contain the IPs in the file ip2.txt and incoming port 9101.
######################################################################################
from ibm_vpc import VpcV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_cloud_sdk_core import ApiException
import ipaddress
import sys
import os

apikey=os.environ['IBMCLOUD_API_KEY']

security_group_pattern = sys.argv[1]
region=sys.argv[2]
fileName=sys.argv[3]

authenticator = IAMAuthenticator(apikey)


service = VpcV1(authenticator=authenticator)

service.set_service_url('https://{}.iaas.cloud.ibm.com/v1'.format(region))

security_group_objs = service.list_security_groups()

file=open(fileName)
ips_to_check=file.read().split('\n')
port_to_check=int(sys.argv[4])
direction=None

if len(sys.argv) < 6:
   direction='inbound'
else:
   direction=sys.argv[5]


for ip in ips_to_check:
    if ip != '':
       print('-------------------------')
       print('IP:   ' + ip)
       ip_address = ipaddress.ip_address(ip)
       for security_group in security_group_objs.get_result()['security_groups']:
          if security_group_pattern in security_group['name']: 
             for rule in security_group['rules'] :
                if 'port_min' in rule:
                   if rule['direction'] == direction and (rule['port_min'] <= port_to_check <= rule['port_max']):
                      cidr = ipaddress.ip_network(rule['remote']['cidr_block'])
                      if ip_address in cidr:
                         print('Security Group: ' + security_group['name'] + '  CIDR: ' + rule['remote']['cidr_block'] + '  Port Range: {}-{}'.format(rule['port_min'], rule['port_max'])) 