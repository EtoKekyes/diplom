from scapy.all import *
import datetime
import os
import subprocess
from collections import Counter

now = datetime.datetime.now() #date and time

def scan(packet):
        if packet.haslayer(Dot11WEP):
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' WEP AP detected, packet sent from WEP AP ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
        if packet.haslayer(Dot11Deauth):
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' Deauthentication attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
        if packet.haslayer(Dot11FCS):
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' PS-Poll attack detected, packet sent from ' + str(packet.addr1).swapcase() +' to device ' + str(packet.addr2).swapcase())
        return
sniff(iface="wlan0", prn=scan, store=False, count=0)



#counter = 0
#while byte:
#    print(byte)
#    byte = file1.read(1)
#    counter += 1
#print(counter)

# len(packet)
# for i in packet:
#     print i.summary()