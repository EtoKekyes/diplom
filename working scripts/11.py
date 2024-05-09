from scapy.all import *
import datetime

def detect_wep_packet(packet):
    if packet.haslayer(Dot11WEP):
        print("[+] WEP packet detected!")
        print(packet.summary())    
    return

print("[*] Starting WEP packet detection...")

sniff(iface="wlan0", store = False, prn=detect_wep_packet)