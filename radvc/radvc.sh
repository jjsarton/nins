#!/bin/sh

### BEGIN INIT INFO
# Provides: radvc
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 3 4 5
# Default-Stop: 0 1 2 6
# Short-Description: 
# Description: correct the /etc/resolv.conf file
### END INIT INFO

start()
{
    PROCS=`pgrep radvc`
    if [ x"$PROCS" = x ]
    then
        echo start radvc
        /usr/sbin/radvc
    fi
}

stop()
{
   echo stop radvc
   pkill /usr/bin/radvc 
}

case $1 in
    start) start;;
    stop) stop;;
    restart) stop; start;;
esac

exit 0;
