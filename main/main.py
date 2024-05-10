from scapy.all import *
import datetime
import os
import subprocess
from collections import Counter

now = datetime.datetime.now() #date and time

def wep(packet):
        if packet.haslayer(Dot11WEP):
            output = ('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' WEP AP detected, packet sent from WEP AP ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
            print(output, end="\r")
        return
sniff(iface="wlan0", prn=wep, store=False, count=0)

def deauth(packet):
    if packet.haslayer(Dot11Deauth):
        print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' Deauthentication attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
    return
sniff(iface="wlan0", prn=deauth, store=False, count=0)

def pspoll(packet):
    if packet.haslayer(Dot11FCS):
        print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' PS-Poll attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
    return
sniff(iface="wlan0", prn=pspoll, store=False, count=0)

#counter = 0
#while byte:
#    print(byte)
#    byte = file1.read(1)
#    counter += 1
#print(counter)

# len(packet)
# for i in packet:
#     print i.summary()