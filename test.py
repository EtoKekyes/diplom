from dataclasses import dataclass, fields
from scapy.all import sniff, Packet, Dot11, Dot11WEP, Dot11FCS, Dot11Deauth, Dot11Disas
from datetime import datetime
import time

now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

deauth_count = 0
last_time = time.time()

def deauth(pkt: Packet):
    global deauth_count, last_time
    current_time = time.time()
    if pkt.haslayer(Dot11Deauth):
        # f = open("deauth.txt", "a")
        # stats = open("stats.txt", "a")
        # print(now,f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
        # print(now,f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
        deauth_count += 1
        if deauth_count >= 4 and current_time - last_time < 0.05:
            print(now,f'Possible DoS Deauthentication attack detected!')                 
            print(now,f' 100 DoS Deauthentication packets detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
            deauth_count = 0
            last_time = current_time
        # f.close()
sniff(iface='wlan0', prn=deauth, store=False, count=0, monitor = True)