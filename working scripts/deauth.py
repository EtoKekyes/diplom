from scapy.all import *
import datetime

# looking for Dot11Deauth AKA Deauthentication Packet
def process_packet(packet):
    if packet.haslayer(Dot11Deauth):
        print(' [ ' +  str(datetime.datetime.now())+ ' ] '+  ' Deauthentication Attack Detected Against Mac Address: ' +   str(packet.addr2).swapcase())
#Running scanner for packet
#sniff(iface="wlan1mon", prn=process_packet, store=False, count=0) #internal wi-fi card
sniff(iface="wlan0", prn=process_packet, store=False, count=0) #tp-link adapter

#sudo python3 deauth.py