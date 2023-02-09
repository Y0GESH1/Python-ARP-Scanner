#!/bin/python3
import scapy.all as scapy 
import datetime as dt
import argparse

def user_in():
    parser = argparse.ArgumentParser(description="Python ARP Scanner")
    parser.add_argument('arguments',metavar='Local IP OR IP Range',help="Enter a single IPV4 address of a valid address range")
    args = parser.parse_args()
    value = args.arguments
    return value


def arp_scan(ip):
    print(f"Sending ARP requests : Current Time {str(dt.datetime.now())}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast =  scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list,unaswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)

    Result_list = []
    for element in answered_list:
        result_dict={"IP":element[1].psrc,"MAC":element[1].hwsrc}
        Result_list.append(result_dict)
        # print(Result_list)
    return Result_list


def show_result(res):
    print("IP\t\t\tMAC")
    for x in res:
        print(f"{x['IP']}\t\t{x['MAC']}")


user_input = user_in()
result = arp_scan(user_input)
show_result(result)
