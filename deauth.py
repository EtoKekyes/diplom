from scapy.all import *
import datetime

# looking for Dot11 AKA Deauthentication Packet
def process_packet(packet):
    if packet.haslayer(Dot11Deauth):
        print(' [ ' +  str(datetime.datetime.now())+ ' ] '+  ' Deauthentication Attack Detected Against Mac Address: ' +   str(packet.addr2).swapcase())
#Running scanner for packet
sniff(iface="wlan0mon", prn=process_packet, store=False, count=0)