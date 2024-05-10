from scapy.all import *
import datetime
import os
import subprocess
from collections import Counter

now = datetime.datetime.now() #date and time
packet_counts = Counter()

##detect WEP Access Points

def wep(packet):
        if packet.haslayer(Dot11WEP): # type: ignore
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' WEP AP detected, packet sent from WEP AP ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
sniff(iface="wlan0", prn=wep, store=False, count=0)

##detect Deauthentication

def deauth(packet):
        if packet.haslayer(Dot11Deauth): # type: ignore
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' Deauthentication attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
sniff(iface="wlan0", prn=deauth, store=False, count=0)

##detect PS-Poll (Power Save Poll protocol)

def pspoll(packet):
        if packet.haslayer(Dot11FCS): # type: ignore
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' PS-Poll attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
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