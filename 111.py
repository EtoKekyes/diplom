import scapy.all as scapy
from prettytable import PrettyTable

table = PrettyTable(['IP', 'MAC Adress'])
def local_scan(ip):
    apr_requests = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_pack = broadcast/apr_requests
    answered_list = scapy.srp(arp_pack, timeout=1, verbose=False)[0]
    for element in answered_list:
        table.add_row([element[1].psrc, element[1].hwsrc])
    print(table)
local_scan('192.168.1.0/24')