
from dataclasses import dataclass, fields
from scapy.all import sniff, Packet, Dot11, Dot11WEP, Dot11FCS, Dot11Deauth, Dot11Disas, Dot11ProbeReq
from datetime import datetime
import time

def now():
    return datetime.now().strftime('%d-%m-%Y %H:%M:%S')

# def deauth(pkt: Packet):
#     if pkt.haslayer(Dot11Deauth):
#         f = open("deauth.txt", "a")
#         stats = open("stats.txt", "a")
#         print('{}'.format(now()),f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
#         print('{}'.format(now()),f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
#         global deauth_count
#         deauth_count += 1
#         if deauth_count >= 100 and time.time()-start_time <= 2:
#             print('{}'.format(now()),f'Possible DoS Deauthentication attack detected!')                 
#             print('{}'.format(now()),f' 100 DoS Deauthentication packets detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
#             deauth_count = 0
#         f.close()
# start_time = time.time()
# deauth_count = 0
# sniff(iface='wlan0', prn=deauth, store=False, count=0, monitor = True)


def disas(pkt: Packet):
    if pkt.type==0 and pkt.subtype==10:
        f = open("disas.txt", "a")
        stats = open("stats.txt", "a")
        print('{}'.format(now()),f' DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
        print('{}'.format(now()),f' DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
        global disas_count
        disas_count += 1
        if disas_count >= 100 and pkt.time - time.time(): 
            print('{}'.format(now()),f'Possible DoS Disassociation attack detected!')                 
            print('{}'.format(now()),f' 100 DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
            disas_count = 0
        f.close()
start_time = time.time()
disas_count = 0

sniff(iface='wlan0', prn=disas, store=False, count=0, monitor = True)

