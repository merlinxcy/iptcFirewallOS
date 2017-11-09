#!/bin/bash
###define the value

###run iptables bash
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -A FORWARD -i eth0 -j ACCEPT
iptables -A FORWARD -i eth1 -j NFQUEUE --queue-num 0

### set ip forward
trigger=`cat /proc/sys/net/ipv4/ip_forward`
echo $trigger
if [ $trigger = 0 ]
then
	echo 'change  ip_forward'
	echo 1 > /proc/sys/net/ipv4/ip_forward
	sysctl -p
fi

###Show
echo 'Show normal tables'
echo ''
iptables -L
echo 'Show nat tables'
echo ''
iptables -t nat -L