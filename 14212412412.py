from scapy.all import *
from datetime import datetime

ap_list = []

def PacketHandler(pkt) :

if pkt.haslayer(Dot11) :
if pkt.type == 0 and pkt.subtype == 4
print str(datetime.now())+" AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


sniff(iface="mon0", prn = PacketHandler)