import scapy
import time

def main():
    pkt_count = 0
    dos_detected = False
    start_time = time.time()

    while True:
        pkt = scapy.sniff(count=1)  # Перехватываем один пакет
        if pkt[0].type == 0 and pkt[0].subtype == 10:  # Проверяем тип и подтип пакета
            pktcount += 1
            if pkt_count >= 100 and time.time() - start_time <= 60:  # Если получено 100 пакетов в течение 60 секунд
                dos_detected = True  # Устанавливаем флаг обнаружения DoS-атаки
                break

    if dos_detected:
        print("DoS-атака обнаружена!")
    else:
        print("DoS-атака не обнаружена")
