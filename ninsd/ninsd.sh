#!/bin/sh
### BEGIN INIT INFO
# Provides:          ninsd
# Required-Start:    $network $local_fs
# Required-Stop:
# Should-Start:
# Should-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Node Information Queries server
# Description: NINSD is a little server which will query attached node
#               for there IPv6 Addresse and name and then update the
#               name server.
### END INIT INFO

if [ -e /etc/default/ninsd ]
then
    . /etc/default/ninsd
elif [ -e exist /etc/sysconfig ]
then
    . /etc/sysconfig/ninsd
fi

if [ x"$NINSD_OPTIONS" = x ]
then
   exit 1;
fi

start()
{
    PROCS=`pgrep ninsd`
    if [ x"$PROCS" = x ]
    then
        echo "start ninsd"
        /usr/sbin/ninsd $NINSD_OPTIONS
    fi
}

stop()
{
   echo "stop ninsd"
   pkill /usr/bin/ninsd
}

status()
{
    PROCS=`pgrep minsd`
    if [ x"$PROCS" = x ]
    then
        echo "ninsd stopped"
    else
        echo "ninsd running"
    fi
}

case $1 in
    start) start;;
    stop) stop;;
    status) status;;
    restart) stop; start;;
esac

exit 0;
