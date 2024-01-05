import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def ping_scan(network_range):
    ans, unans = sr(IP(dst=network_range)/ICMP(), timeout=1, verbose=0)
    for sent, received in ans:
        ip = received[IP].src
        print("Found device with IP:", ip)

network_range = "192.168.0.0/16" 
ping_scan(network_range)