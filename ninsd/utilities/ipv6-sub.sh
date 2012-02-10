#!/bin/sh
###############################################################
#
# This script make the following assumption:
# - The IPv6 internal network must not always be running
#   The user (root) can start and stop the IPv6 access for
#   the network interface configured below
# - The server provide dhcp for IPv4 clients, tayga for
#   NAT64 and named for DNS64
# - Access from IPv4 to IPv6 system is provided
#
# The need configurations file will be created according
# to the few variable you have to set
#
# If you modify the variable SEARCH_LIST, the first domain
# must be the own dynamic domain for the local network
# example:
# SEARCH_LIST=localnet example.org
# 
# localnet is the "privat/ineternal" of the zone managed
# by the server. example.org is an other regular domain
#
# This scrpt can also build all required configurations files
# 
###############################################################

PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH

# EDIT the few variables accordinf to your needs!
# main interface name

EXT_IF=wlan0   # interface to the WAN
INT_IF=eth0    # interface for the local network

# Adresses for the internal network, we use on
IPV6_PREFIX=2001:db8:cafe:dead::
IPV4_NET=10.0.1

# NAT64 must comply with /etc/tayga.conf
IPV64=2001:db8:cafe:beef::
IPV4_TAYGA=10.0.255

# DNS Search list
SEARCH_LIST=dynamic


##############################################
# Set the remaining variables You should
# normaly not touch this.
##############################################
NAMED_CONF=/etc/named.conf

# get main address
EXT_IP=`ip ad sh dev $EXT_IF | sed -n -e '/inet / s/.*inet \(.*\)\/.*/\1/p'`

# set ip adresses and prefix
IPV4_ADDR=${IPV4_NET}.1
IPV6_ADDR=${IPV6_PREFIX}1

IPV4_PREFIX=${IPV4_NET}.0

ZONE=`echo $SEARCH_LIST |awk '{ print $1 }'`
LOCATION=`cat $NAMED_CONF | awk '{ if ( $1 == "directory" ) { print $2 } }' | tr -d '";'`

##############################################
# Helper function for building a new named configuration
##############################################

append_conf()
{
cat <<!
zone "$ZONE" IN {
	type master;
	file "$ZONE.forward";
	allow-query { any; };
	allow-update { ::1; };
	zone-statistics yes;
};
!
}

build_zonefile()
{
cat <<!
\$ORIGIN .
\$TTL 259200
dynamic IN SOA	ns.$ZONE. root.ns.$ZONE. (
        201202774 ; serial
        3600      ; refresh (1 hours)
        600       ; retry (10 minutes)
        86400     ; expire (1 day)
        1800      ; minimum (30 min)
)
NS      ns.$ZONE.
\$ORIGIN $ZONE.
ns      AAAA       $IPV6_ADDR
!
}

insert_option()
{
    echo 'include "dns64.conf";'
}

check_DNS64()
{
    if grep 'include "dns64.conf";' $NAMED_CONF >/dev/null
    then
        echo 0
    else
        echo 1
    fi
}

check_ZONE()
{
    if grep "zone \"$ZONE\" IN" $NAMED_CONF >/dev/null
    then
        echo 0
    else
        echo 1
    fi
}

check_zone_file()
{
    if [ -e $ZONE.forward ]
    then
        echo 0
    else
        echo 1
    fi
}

##############################################
# Build named.conf
##############################################

build_named_conf()
{
    LOCATION=`cat $NAMED_CONF | awk '{ if ( $1 == "directory" ) { print $2 } }' | tr -d '";'`
    INSERT_DNS64=`check_DNS64`
    INSERT_ZONE=`check_ZONE`
    CREATE_ZONE_F=`check_zone_file`

    echo INSERT_DNS64=$INSERT_DNS64
    echo INSERT_ZONE=$INSERT_ZONE
    echo CREATE_ZONE_F=$CREATE_ZONE_F
    echo LOCATION="$LOCATION"

    if [ $INSERT_DNS64 = 1 ]
    then
        sed $NAMED_CONF -e 's/\(options.*{\)/\1\n\tinclude "dns64.conf";/' > $NAMED_CONF.tmp
        cat $NAMED_CONF.tmp > $NAMED_CONF
        rm $NAMED_CONF.tmp
    fi

   if [ $INSERT_ZONE=1 ]
   then
      append_conf >> $NAMED_CONF
   fi
   if [ $CREATE_ZONE_F = 1 ]
   then
       echo ZONE FILE = $LOCATION/$ZONE.forward
       build_zonefile > $LOCATION/$ZONE.forward
       OWN=`ls -l $NAMED_CONF | awk '{ print $3 }'`
       GRP=`ls -l $NAMED_CONF | awk '{ print $4 }'`
       chown $OWN:$GRP $LOCATION/$ZONE.forward
       # create am empty dns64.conf file
       echo "" > $LOCATION/dns64.conf
       chown $OWN:$GRP $LOCATION/dns64.conf

   fi
}

##############################################
# Build tayga.conf and radvd.conf
##############################################

build_tayga_conf()
{
cat <<!
tun-device nat64
ipv4-addr ${IPV4_TAYGA}.1
prefix ${IPV64}/96
dynamic-pool ${IPV4_TAYGA}.0/24
data-dir /var/db/tayga
!
}

build_radvd_conf()
{
cat <<!
interface $INT_IF
{
    IgnoreIfMissing on;
    AdvSendAdvert on;
    MinRtrAdvInterval 300;
    MaxRtrAdvInterval 600;
    prefix ${IPV6_PREFIX}/64
    {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };
    # Recursive DNS server
    RDNSS ${IPV6_ADDR}  { };
    # DNS Search List
    DNSSL ${SEARCH_LIST} { };
};
!
}

setup()
{
    build_tayga_conf  > /etc/tayga.conf
    build_radvd_conf  > /etc/radvd.conf
    # modify /etc/named.conf
    build_named_conf

}

##############################################
# Start and stop
##############################################

NAT64_up()
{
    tayga --mktun
    ip link set up dev nat64
    ip addr add ${EXT_IP} dev nat64
    ip addr add ${IPV6_ADDR} dev nat64

    ip route add ${IPV4_TAYGA}.0/24 dev nat64
    ip route add ${IPV64}/96 dev nat64
    tayga 
}

NAT64_down()
{
    ip link set down dev nat64
    tayga --rmtun 
}

if_up()
{
   ip link set $INT_IF up
   ip ad add $IPV4_ADDR/24 dev $INT_IF
   ip route add $IPV4_PREFIX via $IPV4_ADDR dev $INT_IF
   ip -6 addr add $IPV6_ADDR/64 dev $INT_IF
   ip ro ad $IPV6_PREFIX/64 via $IPV6_ADDR dev $INT_IF
}

if_down()
{
    ip -6 addr del $IPV6_ADDR/64 dev $INT_IF
    ip route del $IPV4_PREFIX via $IPV4_ADDR dev $INT_IF
    ip ad del $IPV4_ADDR/24 dev $INT_IF
    ip link set down dev $INT_IF 
}

nat_up()
{

    iptables -t nat -A POSTROUTING -s $IPV4_PREFIX/24 -j SNAT -o $EXT_IF --to $EXT_IP
    iptables -A FORWARD -i $INT_IF -j ACCEPT

    iptables -t nat  -A POSTROUTING -s $IPV4_TAYGA.0/24 -j SNAT -o $EXT_IF --to $EXT_IP
    iptables -A FORWARD -i nat64 -j ACCEPT

    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
}

nat_down()
{
    sysctl -w net.ipv4.ip_forward=0

    iptables -t nat -D POSTROUTING -s $IPV4_PREFIX/24 -j SNAT -o $EXT_IF --to $EXT_IP
    iptables -D FORWARD -i $INT_IF -j ACCEPT

    iptables -t nat -D POSTROUTING -s $IPV4_TAYGA.0/24 -j SNAT -o $EXT_IF --to $EXT_IP
    iptables -D FORWARD -i nat64 -j ACCEPT
}

start()
{
   nat_up
   if_up
   (
      sleep 4
      radvd -u radvd
    )  &
    echo "dns64 $IPV64/96 {  clients { any; }; };" > $LOCATION/dns64.conf
    NAT64_up
    echo restart named

    if [ -s /bin/systemctl ]
    then
        systemctl restart dhcpd.service
        systemctl restart named.service
    else
        service restart dhcp
        service restart named
    fi
}

stop()
{
    pkill dhcpd
    pkill radvd
    pkill tayga
    if_down
    NAT64_down
    nat_down

    echo "" > $LOCATION/dns64.conf
    if [ -s /bin/systemctl ]
    then
        systemctl restart named.service
    else
        service restart named
    fi
}

status()
{
   ip ad sh dev $INT_IF >/dev/null 2>&1
   if [ $? -eq 0 ]
   then
      echo Local Network Up
   else
      echo Local Network Down
   fi
}

usage()
{
   echo "Syntax: `basename $1` <command>"
   echo
   echo "command is one of the following:"
   echo "	start, stop, restart or setup"
}

if [ "$1" = 0 ]
then
    usage $9
    exit
fi

case $1 in
start)
   start ;;
stop)
   stop ;;
restart)
   stop 
   start ;;
natstart)
   nat start ;;
natstop)
   nat stop ;;
status)
   status;;
setup)
   setup;;
*)
   usage $0;;
esac

