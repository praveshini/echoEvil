#!/bin/sh

service NetworkManager stop     

echo 1 > /proc/sys/net/ipv4/ip_forward  


iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT


hostapd fakeAP/config/hostapd.conf -B
dnsmasq -C fakeAP/config/dnsmasq.conf

