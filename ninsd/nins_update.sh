#!/bin/sh
#set -x
UPDATER=files

case $UPDATER in
named)
    # Update for bind, must run on the same system
    nsupdate
    ;;
files)
    # /etc/hosts based dns, For use with dnsmask
    # you must use the -f hosts_file option and
    # send a SIHGUP to dnsmask
    update_hosts
    ;;
esac

