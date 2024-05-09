from scapy.all import *

def detect_wep(iface):
    # Отправка широковещательного запроса зондирования
    probe_req = RadioTap()/ Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff")/ Dot11ProbeReq(ssid="any")
    probe_req.show()
    sendp(probe_req, iface=iface, count=10)

    # Анализ полученных ответов
    sniff(iface=iface, count=10, filter="type mgt subtype probe resp", prn=lambda pkt: pkt.show())

if __name__ == "__main__":
    iface = "wlan0"  # Замените на ваш сетевой интерфейс Wi-Fi
    detect_wep(iface)