#!/usr/bin/env python3

from dataclasses import dataclass, fields
from scapy.all import sniff, Packet, Dot11WEP, Dot11FCS, Dot11Deauth, Dot11Disas
from datetime import datetime

now = datetime.now()

def wep(pkt: Packet):
    if pkt.haslayer(Dot11WEP):
        print("[",now,"]",f"WEP AP detected, packet sent from {pkt.addr1} to device {pkt.addr2}")

def pspoll(pkt: Packet):
    if pkt.haslayer(Dot11FCS):
        print("[",now,"]",f"PS-Poll attack detected, packet sent from {pkt.addr1} to device {pkt.addr2}")

def deauth(pkt: Packet):
    #print(pkt.summary())
    if pkt.haslayer(Dot11Deauth):
        print("[",now,"]",f'DoS Deauthentication attack detected, packet sent from {pkt.addr1} to device {pkt.addr2}')

def disas(pkt: Packet):
    if pkt.type==0 and pkt.subtype==12:
        print("[",now,"]",f'DoS Disassociation attack detected, packet sent from {pkt.addr1} to device {pkt.addr2}')


@dataclass
class Config:
    iface: str = "wlan0"

def change_config(conf: Config):
    match input(f"Select option: (iface): "):
        case "iface":
            conf.iface = input("what wlan to use: ")
        case _name:
            print(f"Invalid option: {_name}!")

def main():
    conf = Config()
    def start(func):
        print("Starting sniffer")
        sniff(iface=conf.iface, prn=func, store=False, count=0, monitor = True)
    while True:
        print(f"\nUsing {conf}")
        match input("Select monitor mode: (pspoll, deauth, disas, wep, config, exit): "):
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
            case "exit": 
                break
            case _name: 
                print(f"Invalid mode: {_name}!")

if __name__ == "__main__":
    main()