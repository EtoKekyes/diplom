# from scapy.all import *

# # Define the target MAC address and ESSID
# target_mac = "0e:98:ab:74:cf:a0"
# essid = "MVG"

# # Generate a WEP packet
# wep_pkt = RadioTap() / Dot11(addr1=target_mac, addr2="50:ff:20:6a:e5:a8", addr3=target_mac) / Dot11WEP() / Dot11Auth() / Raw(essid)

# # Send the packet
# sendp(wep_pkt, iface="wlan")

from scapy.all import *

frame = Dot11WEP()
sendp(frame, iface='wlan1', inter=0.050, loop=1, monitor=True)