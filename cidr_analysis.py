###################################################################################
# This application receives a list of IPs in an input file and perform analysis of
# possible combinations for CIDRs based on the IP list. The program tries to find 
# the common ancestral CIDR for the set of IPs and starts splitting up in smaller
# subnets, eliminating CIDRs with no matched IPs and showing in the standard output
# the number of available/matched IPs for each subnet with matched IPs.
# The purpose of this application is to facilitate the analysis of needed security 
# group and ACL rules based on a list of source IPs.
#
# Usage:
#       python3 cidr_analysis.py <file_txt_file>, where file_txt_file contains a list
#         of IPs, one per line
#
# Examples:
# 1) Reading IPs from an existent file:
#      python3 ~/cidr_analysis.py /tmp/ips.txt
#
# 2) Reading as an output of a command:
#      cat /tmp/ip2.txt | grep -E "^10." |python3 ~/cidr_analysis.py /dev/stdin 
#
##################################################################################
import ipaddress
import sys

#####################################################################
# Get a list of subnets and try to split to the next CIDR and find
# the matched IP addresses. Subnets that don't have any IP in it 
# are discarded.
#
# Parameters:
# subnets: list of ipaddress.ip_network objects
# ips: list of IPs to match
#
# Returns: a list of children subnets that has at least 1 IP in it.
#  It is a complex object with the following schema:
#   - subnet: ipaddress.ip_network object
#   - cidr: string with the network CIDR
#   - prefix_len: Mask bit of this subnet
#   - available_ip_addresses: number of IP addresses of this subnet
#   - matched_ip_addresses: number of matched IP addresses in the list
######################################################################
def split_and_find_subnets_with_matching_addresses(subnets, ips):
    subnets_with_ips_included=[]
    for subnet in subnets:
        splitted_subnets=list(subnet.subnets())
        for splitted_subnet in splitted_subnets:
            matched_ips=0
            available_ip_addresses=splitted_subnet.num_addresses
            matched_ip_addresses=[]
            for ipStr in ips:
                ip=ipaddress.ip_address(ipStr)
                if ip in splitted_subnet:
                   matched_ips=matched_ips+1
                   matched_ip_addresses.append(ipStr)
            if matched_ips > 0:
               subnets_with_ips_included.append({
                'subnet': splitted_subnet,
                'cidr': splitted_subnet.with_prefixlen,
                'prefix_len': splitted_subnet.prefixlen, 
                'available_ip_addresses': available_ip_addresses,
                'matched_ip_addresses': matched_ips,
                'ips' : matched_ip_addresses
            })
    return subnets_with_ips_included

##################################################################################
# MAIN PROGRAM LOGIC    
# Author: Marcos Vieira
##################################################################################
fileName=sys.argv[1]
file=open(fileName)
ips_in_file=file.read().split('\n')

ips_to_check=[]
for ip in ips_in_file:
    if ip != '':
       ips_to_check.append(ip)


print('IPs to analyze: {}'.format(len(ips_to_check)) )

first_ip=ipaddress.ip_address(ips_to_check[0])
other_ips=ips_to_check[1:]
max_distance=0

for ipStr in other_ips:
    if ipStr != '':
        ip=ipaddress.ip_address(ipStr)
        diff=int(first_ip) ^ int(ip)
        if diff > max_distance:
           max_distance=diff

binary_str=bin(max_distance)
binary_size=len(binary_str) - 2
cidr=32 - binary_size

first_ip_binary_representation=format(int(first_ip),'#032b')
new_first_ip=int(first_ip) >> binary_size
new_first_ip=new_first_ip << binary_size

print('Binary representation of the common denominator:   ' + binary_str)
print('Binary representation of the first IP in the list: ' + first_ip_binary_representation)
print('Binary representation of the found CIDR:           ' + format(new_first_ip,'#032b'))

new_ip=ipaddress.ip_address(new_first_ip)
new_netmask=ipaddress.ip_network('{}/{}'.format(new_ip, cidr))
print('**** Common CIDR found: {} ({} IP Addresses)'.format(new_netmask, new_netmask.num_addresses))

subnets_found_by_cidr=[]
subnets_found_by_cidr.append([{
    'subnet': new_netmask,
    'cidr' : new_netmask.with_prefixlen,
    'prefix_len': cidr,
    'available_ip_addresses': new_netmask.num_addresses,
    'matched_ip_addresses' : len(ips_to_check)
}])


for prefix in range(1, 32 - cidr):
    previous_key=prefix-1
    previous_subnets=[]
    for previous_obj in subnets_found_by_cidr[previous_key] : 
        if previous_obj['available_ip_addresses'] > previous_obj['matched_ip_addresses'] :
           previous_subnets.append(previous_obj['subnet'])
    current_result=split_and_find_subnets_with_matching_addresses(previous_subnets, ips_to_check)
    current_key=prefix
    subnets_found_by_cidr.append(current_result)



idx=0
subnet_list_length=len(subnets_found_by_cidr)
for subnet_found in subnets_found_by_cidr:
    print('--------------------------------------------------------------------------------------------')
    print('** Subnet Split Analysis for prefix length {} ({} CIDRs)'.format(cidr+idx, len(subnet_found)))
    if 0 < idx < subnet_list_length - 1:
        if len(subnets_found_by_cidr[idx-1]) == len(subnet_found) and len(subnets_found_by_cidr[idx+1]) == len(subnet_found) :
            print('********** NO CHANGES ***********')
            idx=idx+1
            continue
    
    not_grouped_ips=[]
    grouped_cidrs=0
    for one_subnet in subnet_found:
        match_ratio=one_subnet['matched_ip_addresses'] / one_subnet['available_ip_addresses']
        message=''
        if(match_ratio==1):
           message='(*** Perfect Match ***)'
        if(0.5 <= match_ratio < 1) and one_subnet['matched_ip_addresses'] > 1:
           message='(*** Good Match ***)'
        
        if one_subnet['matched_ip_addresses'] == 1:
           not_grouped_ips.append(one_subnet['ips'][0] + '/32')
        else: 
           print('CIDR: {:<20} Available IP Addresses: {:>8} Number of matches: {:>8} {}'.format(one_subnet['cidr'], one_subnet['available_ip_addresses'], one_subnet['matched_ip_addresses'], message)) 
           if 'ips' in one_subnet:
              print('IPs: {}'.format(','.join(one_subnet['ips'])))
              print('')
           grouped_cidrs=grouped_cidrs+1
    if (len(not_grouped_ips) > 0):
       print('- Not grouped IPs: {}'.format(','.join(not_grouped_ips)))
    print('({} CIDRs, {} not grouped IPs)'.format(grouped_cidrs, len(not_grouped_ips)))
    idx=idx+1