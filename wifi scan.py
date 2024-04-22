from scapy.all import *

def get_connected_ips(interface, wifi_ssid):
    connected_ips = set()

    def packet_callback(packet):
        if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
            if packet.info.decode() == wifi_ssid:
                connected_ips.add(packet.addr2)

    sniff(iface=interface, prn=packet_callback, store=0, timeout=10)

    return connected_ips

if __name__ == "__main__":
    wifi_interface = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"  # Change this to your WiFi interface name
    wifi_ssid = "MVG"  # Change this to your WiFi SSID

    connected_ips = get_connected_ips(wifi_interface, wifi_ssid)
    print("Connected IP addresses:")
    for ip in connected_ips:
        print(ip)