#################################################################################
# This small Python program receives a list of IPs and identifies which ACL rules
# handle that IP addresses. It uses IBM Cloud VPC SDK to retrieve the subnet and ACL based 
# on the subnet name and uses ipaddress Python library to determine the ACL rule
# number that IP address is handled, returning a full description of the correspondent ACL.
#
# Environment Variables:
# IBMCLOUD_API_KEY (required): IBM Cloud API Key of an user with access to VPC infrastructure.
#
# Usage:
# python3 compare_ips_acl.py <subnet_name> <region> <ips_file> <direction> <protocol> <src_ip_port> <dst_ip_port>
# 
# <src_ip_port> and <dst_ip_port> uses a notation <ip_address>:<port>. <port> is optional.
# Uses the special word IP to instructs the application to replace it by each ip address in the text file.
#
# Example:
# 
# Supposing you have the following IPs in a text file /tmp/ips.txt:
# 10.237.78.91
# 10.145.92.94
# 10.50.251.37
#
# python3 compare_ips_acl.py wdcaz2-ace-subnet-hpc us-east /tmp/ips.txt inbound tcp IP 10.254.56.10:7870
#         check what ACL rules match each of the three IPs in the file as source IPs and destination IP 10.254.56.10, port 7870,
#         protocol tcp, considering the subnet wdcaz2-ace-subnet-hpc and 10.254.56.10 is an IP inside of that subnet (inbound connection)
#
# Output:
# Network name found. Related ACL: acl-wdc-ace-hpc-default (r014-480ceaff-aba9-4a4c-9598-619f4ec338c4)
# -------------------------------------------------------------------------------------
# Traffic type: inbound, protocol: tcp  ['10.237.78.91'] ---> ['10.254.56.10', '7870']
# Rule          #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
# -------------------------------------------------------------------------------------
# Traffic type: inbound, protocol: tcp  ['10.145.92.94'] ---> ['10.254.56.10', '7870']
# Rule          #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
# -------------------------------------------------------------------------------------
# Traffic type: inbound, protocol: tcp  ['10.50.251.37'] ---> ['10.254.56.10', '7870']
# Rule          #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
#
#
# python3 compare_ips_acl.py wdcaz2-ace-subnet-hpc us-east /tmp/ips.txt outbound tcp 10.254.56.10 IP:8443
#         check what ACL rules match the 10.254.56.10 as source IP with destination to the three IPs in the file, port 8443, 
#         protocol tcp, considering the subnet wdcaz2-ace-subnet-hpc and 10.254.56.10 is an IP inside of that subnet (outbound connection)
#
# Output:
# Network name found. Related ACL: acl-wdc-ace-hpc-default (r014-480ceaff-aba9-4a4c-9598-619f4ec338c4)
# -------------------------------------------------------------------------------------
# Traffic type: outbound, protocol: tcp  ['10.254.56.10'] ---> ['10.237.78.91', '8443']
# Rule          #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow
# -------------------------------------------------------------------------------------
# Traffic type: outbound, protocol: tcp  ['10.254.56.10'] ---> ['10.145.92.94', '8443']
# Rule          #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow
# -------------------------------------------------------------------------------------
# Traffic type: outbound, protocol: tcp  ['10.254.56.10'] ---> ['10.50.251.37', '8443']
# Rule          #13(outbound): Src CIDR:10.254.56.0/21 Src Port:1-65535     Dst CIDR:10.0.0.0/8  Dst Port:1-65535  Prot:tcp  Action:allow
# Reverse Rule  #13(inbound): Src CIDR:10.0.0.0/8 Src Port:1-65535     Dst CIDR:10.254.56.0/21  Dst Port:1-65535  Prot:tcp  Action:allow 
#
######################################################################################

from ibm_vpc import VpcV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_cloud_sdk_core import ApiException
import ipaddress
import sys
import os

def check_firewall_path(src_ip, src_port, dst_ip, dst_port, protocol, current_path, reverse_path):
    find_rule(ipaddress.ip_address(src_ip), src_port, ipaddress.ip_address(dst_ip), dst_port, protocol, current_path, 'Rule         ')
    find_rule(ipaddress.ip_address(dst_ip), dst_port, ipaddress.ip_address(src_ip), src_port, protocol, reverse_path, 'Reverse Rule ')

def find_rule(src_ip, src_port, dst_ip, dst_port, protocol, rules, text_prefix):
    rule_number=0
    for rule in rules:
        valid_rule = False
        rule_number=rule_number+1
        source = ipaddress.ip_network(rule['source'])
        destination = ipaddress.ip_network(rule['destination'])
        if src_ip in source and dst_ip in destination:
           if rule['protocol'] == 'all':
              print('{} #{}({}): Src CIDR:{}    Dst CIDR :{} Prot:all  Action:{}'.format( text_prefix, rule_number, rule['direction'], rule['source'], rule['destination'], rule['action']))
              break
           else:
              if rule['protocol'] == protocol:
                 if (src_port == 0 or rule['source_port_min'] <= src_port <= rule['source_port_max']) and (dst_port == 0 or rule['destination_port_min'] <= dst_port <= rule['destination_port_max']):
                    print('{} #{}({}): Src CIDR:{} Src Port:{}-{}     Dst CIDR:{}  Dst Port:{}-{}  Prot:{}  Action:{}'.format( text_prefix, rule_number, rule['direction'], rule['source'], rule['source_port_min'], rule['source_port_max'], rule['destination'],  rule['destination_port_min'], rule['destination_port_max'], rule['protocol'], rule['action']) )
                    break



## MAIN
apikey=os.environ['IBMCLOUD_API_KEY']

subnet_name=sys.argv[1]
region=sys.argv[2]
fileName=sys.argv[3]
protocol=sys.argv[5]
src_ip_port=sys.argv[6]
dst_ip_port=sys.argv[7]

authenticator = IAMAuthenticator(apikey)

service = VpcV1(authenticator=authenticator)
service.set_service_url('https://{}.iaas.cloud.ibm.com/v1'.format(region))

file=open(fileName)
ips_to_check=file.read().split('\n')

direction=sys.argv[4]

network_acl_id = None
subnets = service.list_subnets()
for subnet in subnets.get_result()['subnets']:
    if subnet['name'] == subnet_name:
       print('Network name found. Related ACL: {} ({})'.format(subnet['network_acl']['name'],subnet['network_acl']['id']))
       network_acl_id = subnet['network_acl']['id']

if network_acl_id is not None:
   network_acl = service.get_network_acl(network_acl_id)
   incoming_rules = []
   outgoing_rules = []
   for rule in network_acl.get_result()['rules']:
       if rule['direction'] == 'inbound':
          incoming_rules.append(rule)
       if rule['direction'] == 'outbound':
          outgoing_rules.append(rule)

   for ip in ips_to_check:
       if ip == '':
          continue
       src_ipport_arr=src_ip_port.replace('IP', ip).split(':')
       dst_ipport_arr=dst_ip_port.replace('IP', ip).split(':')
       src_port=0
       dst_port=0
       if len(src_ipport_arr) > 1:
          src_port=int(src_ipport_arr[1])
       if len(dst_ipport_arr) > 1:
          dst_port=int(dst_ipport_arr[1])
       print('-------------------------------------------------------------------------------------')
       print('Traffic type: {}, protocol: {}  {} ---> {}'.format(direction, protocol, str(src_ipport_arr), str(dst_ipport_arr)))
       if direction == 'outbound':
          check_firewall_path(src_ipport_arr[0], src_port, dst_ipport_arr[0], dst_port, protocol, outgoing_rules, incoming_rules)
       else:
          check_firewall_path(src_ipport_arr[0], src_port, dst_ipport_arr[0], dst_port, protocol, incoming_rules, outgoing_rules)
