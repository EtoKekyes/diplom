import scapy.all

def scaner (ipadress):
    arp_request = scapy.all.ARP(pdst=ipadress)
    broadcast = scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answer_yes, answer_no = scapy.all.srp(arp_request_broadcast, timeout = 1)
    print (answer_yes.summary())
    print (answer_no.summary())
    #print (broadcast.summary())
    #scapy.all.ls(scapy.all.Ether())
    #arping()
    #scapy.all.arping(ipadress)
    #arp_request = scapy.all.ARP(pdst=ipadress)
    #print (arp_request.summary())
    #scapy.all.ls (scapy.all.ARP())
scaner('192.168.0.1/24')