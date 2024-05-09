from scapy.all import *

def detect_deauth(pkt):
    if pkt.haslayer(Dot11Deauth):
        print("Possible deauthentication attack detected:")
        print(pkt.summary())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dot11deauth_detection.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    print("Starting DoT11 deauthentication attack detection on interface:", interface)
    sniff(iface=interface, prn=detect_deauth, store=0)