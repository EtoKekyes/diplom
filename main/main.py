from scapy.all import *
import datetime
import os
import subprocess

now = datetime.datetime.now()

##detect WEP AP

#counter = 0
#while byte:
#    print(byte)
#    byte = file1.read(1)
#    counter += 1

#print(counter)


def detect_wep_ap(packet):
    if packet.haslayer(Dot11WEP): # type: ignore
        print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' WEP AP detected, packet sent from' + str(packet.addr1).swapcase() +' to ' + str(packet.addr2).swapcase())
        print(packet.summary())
    return
sniff(iface="wlan0", prn=detect_wep_ap, store=False, count=0)

# len(packet)
# for i in packet:
#     print i.summary()