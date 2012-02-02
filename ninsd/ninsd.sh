#!/bin/sh

if [ -e /etc/default/ninsd ]
then
    source /etc/default/ninsd
elif [ -e exist /etc/sysconfig ]
then
    source /etc/sysconfig/ninsd
fi

if [ x"$ARGS" = x ]
then
   exit 1;
fi

start()
{
    PROCS=`pgrep minsd`
    if [ x"$PROCS" = x ]
    then
        /usr/sbin/ninsd $ARGS
    fi
}

stop()
{
   pkill /usr/bin/ninsd
}


case $1 in
    start) start;;
    stop) stop;;
    restart) stop; start;;
esac

exit 0;
