#!/bin/sh
# Example for unbound dynamic update

while read cmd sub name ttl typ addr
do
	case $sub in
	delete) unbound-control local_data_remove "$name";;
	add) unbound-control local_data "$name IN $typ $addr";;
	esac
done
