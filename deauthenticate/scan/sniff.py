from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap
import time
from datetime import datetime
import os
from threading import Thread


def switch_channel(interface: str, timeout_seconds, channel: int = 1):
   
    start_time = datetime.now()
    channel = channel
    while (datetime.now() - start_time).seconds < timeout_seconds:
        channel = (channel % 14) + 1
        os.system('iwconfig {} channel {}'.format(interface, channel))
        time.sleep(1)
        #print("channel")


def getClients(pkt):
    
    
    if pkt.haslayer(Dot11):  
        bssid = pkt[Dot11].addr3 
        target_bssid = a 
        if (pkt.addr2 == target_bssid or pkt.addr3 == target_bssid) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
            if pkt.addr1 not in voc and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
                print(pkt.addr1)
                voc.append(pkt.addr1)


def clientFind(interface, BSSID):
    
    global voc
    voc = []
    global a
    a = BSSID
    interupted = False
    try:
        sniff(iface=interface, prn=getClients, stop_filter=interupted)
    except KeyboardInterrupt:
        interupted = True


def findNetwork(interface):
    
    known = {}

    def callback(pkt):
        if pkt.haslayer(Dot11): 
            
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                src = pkt[Dot11].addr2  
                if src not in known:  
                    ssid = pkt[Dot11Elt][0].info.decode()  

                    
                    channel = pkt[RadioTap].channel

                    
                    print("SSID: '{}', BSSID: {}, channel: {}".format(
                        ssid, src, channel))
                    known[src] = (ssid, channel)
                    #print(known)
                    #print("appned")

    channel_thread = Thread(target=switch_channel,
                            args=(interface, 10), daemon=True)
    channel_thread.start()
    print('----------------------------------------')
    print('NETWORKS')
    print('----------------------------------------')
    sniff(prn=callback, iface=interface) # timeout=60
    #print("snif")
    channel_thread.join()  

    #print("hi",known)
    return known

