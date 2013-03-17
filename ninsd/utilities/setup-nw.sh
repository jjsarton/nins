#!/bin/sh
##########################################
# Setup our IPv6 network
# This is only a little example!
##########################################

IFACE=eth0
NET4=192.168.178

ROUTER=$NET4.1
IPNS=$NET4.2

ip link set dev $IFACE up
PREFIX=`getprefix`
ADDR=`calcsubnet -p $PREFIX -o 2`

ip addr add $ADDR/64 dev $IFACE
ip route add default via $ADDR dev $IFACE

###########################################
# Build the host and addn file for dnsmasq
###########################################
cat <<!
127.0.0.1  localhost.localdomain localhost
::1        localhost6.localdomain6 localhost6
${PREFIX}2 ns.domain ns
!
cat > /etc/dnsmasq.conf <<!
interface=$IFACE
expand-hosts
domain=domain
dhcp-range=$NET4.10,$NET4.254,10m
dhcp-range=${PREFIX}a,${PREFIX}ff,10m
dhcp-authoritative
dhcp-leasefile=/var/run/dnsmasq/dnsmasq.leases
server=$ROUTER
dhcp-option=option:router,$ROUTER
!

###########################################
# get prefix delegation and the base prefix
###########################################
dibbler-client start

BP=`sed -n 's/.*<prefix.*>\(.*\)<\/prefix>/\1/p' /var/lib/dibbler/client-CfgMgr.xml`

###########################################
# Build the tinc-up file again
# I expect 2 vaiable within this file,
# server_ip whixh contain the main IP6 Addr
# for the server and
# vpn_subnet, ehich hold the subnet for our
# vpn service
###########################################

sed -e "s/server_ip=.*/server_ip=${ADDR}/" \
    -e "s/vpn_subnet=.*/vpn_subnet=${BP}\/64/" \
    /etc/tinc/homenetwork/tinc-up \
    > /tmp/tinc-up
mv /tmp/tinc-up /etc/tinc/homenetwork/tinc-up

###########################################
# start our daemon
###########################################

/usr/sbin/dnsmasq -x /var/run/dnsmasq/dnsmasq.pid -u dnsmasq \
  -s domain \
  -7 /etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new -K

ninsd -i eth0 -s /usr/local/bin/update_dnsmasq.sh -P 530

tincd -n homenetwork

