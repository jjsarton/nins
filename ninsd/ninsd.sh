#!/bin/sh

if [ -e /etc/default/ninsd ]
then
    . /etc/default/ninsd
elif [ -e exist /etc/sysconfig ]
then
    . /etc/sysconfig/ninsd
fi

if [ x"$NINSD_IFACE" = x ]
then
   exit 1;
fi

start()
{
    PROCS=`pgrep minsd`
    if [ x"$PROCS" = x ]
    then
        echo "start ninsd"
        /usr/sbin/ninsd $NINSD_IFACE $NINSD_MAP
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
