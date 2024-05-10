from scapy.all import *
import subprocess
import time
import sys
import os

while True:
    user_input = input("Enter a command (deauth, pspoll, wep, stats, exit): ")

    if user_input == "exit":
        break
    elif user_input == "help":
        print("Available commands: deauth, pspoll, wep, stats, exit")
    elif user_input == "deauth":
        subprocess.run(['python3', '/home/kali/Desktop/diplom/diplom/main/deauth.py'], check = True)
        #subprocess.Popen(["/home/kali/Desktop/diplom/diplom/main/deauth.py"], shell = True)
    # elif user_input == "pspoll":

    # elif user_input == "wep":

    # elif user_input == "stats":