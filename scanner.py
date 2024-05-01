import scapy.all as scapy

def scan (ipadress):
    arp_request = scapy.ARP(pdst=ipadress)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = arp_request/broadcast
    answer_yes, answer_no = scapy.srp(arp_request_broadcast, timeout=1)

    print ("yes:", answer_yes.summary())
    print ("no:", answer_no.summary())
    
scan ('192.168.1.1/24')