from scapy.all import *

def sniff_packet():
    sniff(iface="MediaTek Wi-Fi 6 MT7921 Wireless LAN Card", prn=process_packet)

def process_packet(packet):
    # Process the captured Wi-Fi packet here
    print(packet.summary())

sniff_packet()
def process_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:  # 0: Management frame, 8: Beacon frame
            # Extract relevant information from the Beacon frame
            print("SSID:", packet.info.decode())
            print("Source MAC Address:", packet.addr2)