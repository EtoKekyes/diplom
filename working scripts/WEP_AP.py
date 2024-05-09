# from scapy.all import *
# import datetime

# def detect_wep_packet(packet):
#     if packet.haslayer(Dot11WEP):
#         print("[+] WEP packet detected!")
#         print(packet.summary())    
#     return

# print("[*] Starting WEP packet detection...")

# sniff(iface="wlan0", prn=detect_wep_packet)

from scapy.all import *
import datetime

# looking for Dot11FCS AKA PS-Poll Packet
def process_packet(packet):
    if packet.haslayer(Dot11WEP):
        print(' [ ' +  str(datetime.datetime.now())+ ' ] '+  ' WEP AP detected      MAC: ' +   str(packet.addr1).swapcase())
#Running scanner for packet
sniff(iface="wlan0", prn=process_packet, store=False, count=0) #internal wi-fi card
#sniff(iface="wlan0", prn=process_packet, store=False, count=0) #tp-link adapter

#sudo python3 pspoll.py