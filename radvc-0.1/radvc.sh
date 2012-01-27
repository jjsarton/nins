#!/bin/sh

start()
{
    PROCS=`pgrep minsc`
    if [ x"$PROCS" = x ]
    then
        /usr/sbin/radvc
    fi
}

stop()
{
   pkill /usr/bin/radvc 
}

case $1 in
    start) start;;
    stop) stop;;
    restart) stop; start;;
esac

exit 0;
