from scapy.all import *
import datetime
import os
import subprocess
from collections import Counter

now = datetime.datetime.now() #date and time
packet_counts = Counter()

##detect WEP AP

def detect_wep_ap(packet):
    while True:
        if packet.haslayer(Dot11WEP): # type: ignore
            print('[' + now.strftime("%Y/%m/%d %I:%M:%S") + ']' + ' WEP AP detected, packet sent from ' + str(packet.addr1).swapcase() +' to ' + str(packet.addr2).swapcase(), end='\r')
sniff(iface="wlan0", prn=detect_wep_ap, store=False, count=0)


#counter = 0
#while byte:
#    print(byte)
#    byte = file1.read(1)
#    counter += 1
#print(counter)

# len(packet)
# for i in packet:
#     print i.summary()