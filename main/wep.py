from scapy.all import *
import datetime

def wep(pkt):
    while True:
        if pkt.haslayer(Dot11WEP):
            output = str(datetime.datetime.now()) + ' WEP AP detected, packet sent from ' + str(pkt.addr1) + ' to device ' + str(pkt.addr2)
            print(output, end='\r')
            time.sleep(5)
        return
sniff(iface="wlan0", prn=wep, store=False, count=0)