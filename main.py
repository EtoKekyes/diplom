#!/usr/bin/env python3

from dataclasses import dataclass, fields
from scapy.all import sniff, Packet, Dot11, Dot11WEP, Dot11FCS, Dot11Deauth, Dot11Disas
from datetime import datetime, time

now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def wep(pkt: Packet):
    if pkt.haslayer(Dot11WEP):
        f = open("wep.txt", "a")
        stats = open("stats.txt", "a")
        print(now,f' WEP AP detected with MAC: {pkt.addr1}', file = f,sep="")
        print(now,f' WEP AP detected with MAC: {pkt.addr1}', file = stats,sep="")
        print(now,f' WEP AP detected with MAC: {pkt.addr1}', sep="")

def pspoll(pkt: Packet):
    #if pkt.haslayer(Dot11FCS):
    if pkt.type==1 and pkt.subtype==10:
        f = open("pspoll.txt", "a")
        stats = open("stats.txt", "a")
        print(now,f' PS-Poll packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
        print(now,f' PS-Poll packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
        global pspoll_count
        pspoll_count += 1
        if pspoll_count >= 100:
            print(now,f'Possible PS-Poll attack detected!')                 
            print(now,f' 100 PS-Poll packets detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
            pspoll_count = 0
        f.close()
pspoll_count = 0   

def deauth(pkt: Packet):
    if pkt.haslayer(Dot11Deauth):
        f = open("deauth.txt", "a")
        stats = open("stats.txt", "a")
        print(now,f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
        print(now,f' DoS Deauthentication packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
        global deauth_count
        deauth_count += 1
        if deauth_count >= 100 and pkt.time - start_time <= 0.05:
            print(now,f'Possible DoS Deauthentication attack detected!')                 
            print(now,f' 100 DoS Deauthentication packets detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
            deauth_count = 0
        f.close()
deauth_count = 0
start_time = time.time()

def disas(pkt: Packet):
    if pkt.type==0 and pkt.subtype==12:
        f = open("disas.txt", "a")
        stats = open("stats.txt", "a")
        print(now,f' DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = f, sep="")
        print(now,f' DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', file = stats, sep="")
        global disas_count
        disas_count += 1
        if disas_count >= 100:
            print(now,f'Possible DoS Disassociation attack detected!')                 
            print(now,f' 100 DoS Disassociation packet detected, packet sent from {pkt.addr1} to device {pkt.addr2}', sep="")
            disas_count = 0
        f.close()
disas_count = 0

@dataclass
class Config:
    iface: str = "wlan0"

def change_config(conf: Config):
    match input(f"Select option: (iface): "):
        case "iface":
            conf.iface = input("what wlan to use: ")
        case _name:
            print(f"Invalid option: {_name}!")

def stats():
    while True:
        match input(f"Select stats (pspoll, deauth, disas, wep, count, back): "):
            case "pspoll":
                with open("pspoll.txt", "r") as f:
                    for last_line in f:
                        pass
                    print("\nLatest PS-Poll packet detected:", last_line)
            case "deauth":
                with open("deauth.txt", "r") as f:
                    for last_line in f:
                        pass
                    print("\nLatest DoS Deauthentication packet detected:", last_line)
            case "disas":
                with open("disas.txt", "r") as f:
                    for last_line in f:
                        pass
                    print("\nLatest DoS Disassociation packet detected:", last_line)
            case "wep":
                with open("wep.txt", "r") as f:
                    for last_line in f:
                        pass
                    print("\nLatest WEP AP detected:", last_line)
            case "count":
                f = open("stats.txt", 'r')
                contents = f.read()
                wep = contents.count("WEP AP")
                pspoll = contents.count("PS-Poll")
                disas = contents.count("Disassociation")
                deauth = contents.count("Deauthentication")
                print("|-------------------------------------------------------------------------------|\n"
                    "| Current stats:""\n"
                    "| PS-Poll packets detected =",pspoll, "\n"
                    "| DoS Deauthentication packets detected =",deauth, "\n"
                    "| DoS Disassociation packets detected =",disas, "\n"
                    "| WEP APs detected =",wep)
                f.close()
            case "back":
                break
            case _name: 
                print(f"Invalid mode: {_name}!")

def main():
    conf = Config()
    def start(func):
        print("Starting sniffer")
        sniff(iface=conf.iface, prn=func, store=False, count=0, monitor = True)
    while True:
        print(f"\nUsing {conf}")
        match input("Select monitor mode: (pspoll, deauth, disas, wep, config, stats, exit): "):
            case "pspoll": 
                start(pspoll)
            case "wep": 
                start(wep)
            case "deauth": 
                start(deauth)
            case "disas":
                start(disas)
            case "config": 
                change_config(conf)
            case "stats":
                stats()
            case "exit": 
                break
            case _name: 
                print(f"Invalid mode: {_name}!")

if __name__ == "__main__":
    main()