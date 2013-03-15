#!/bin/sh
#########################################################
# This is an example for updating various name server.
# 
# You must adapt this to your server environment.
# The scripts/programme are included here and must be
# installed nanually.
#
#########################################################
#set this
UPDATER=named

#UPDATER=dnsmasq
#ADDN_FILE=/var/run/dnsmask/hosts


case $UPDATER in
named)
    # Update for bind, must run on the same system
    nsupdate
    ;;
unbound)
    #
    update-unbound.sh
    pkill -SIGHUP dnsmasq
dnsmasq)
    update_hosts $ADDN_FILE
    pkill -SIGHUP dnsmasq
    ;;
esac

