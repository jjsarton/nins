#!/bin/sh
# This script send the datas from the ninsd daemon
# to the ninsd daemon located on the name server
# system.
# You may also use ncat or netcat according the
# the installed binary.

# ninsd listen only for IPv6 si we use the -6 option
# ns ist tje name or IPv6 Adresse of the name server
# 530 is the port we use.

nc -6 ns 530
