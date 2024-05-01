#airodump-ng -d "target's BSSID" -c "target's channel number" "wireless adapter monitor mode name"
#MediaTek Wi-Fi 6 MT7921 Wireless LAN Card
import sys
from scapy.all import *

def detect_deauth(pkt):
    if pkt.haslayer(Dot11Deauth):
        print("Possible deauthentication attack detected:")
        print(pkt.summary())

def detect_disassoc(pkt):
    if pkt.haslayer(Dot11Disassoc):
        print("Possible disassociation attack detected:")
        print(pkt.summary())

interface = "WIFI@REALTEK"
def main(interface):
    print("Starting Wi-Fi attack detection on interface:", interface)
    sniff(iface=interface, prn=detect_deauth, store=0)
    sniff(iface=interface, prn=detect_disassoc, store=0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wifi_attack_detection.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    main(interface)