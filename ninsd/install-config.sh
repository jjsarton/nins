#!/bin/sh

get_args()
{
   {
   echo Ninsd must be bind to an ethernet interface.
   echo This interface is the intetrface on which the
   echo clients are attached. This van be eth0, eth1 or
   echo an other interface on your system.
   echo Entering q or Q will create the configuration file.
   echo /etc/sysconfig/ninsd or /etc/default/ninsd
   echo 'with "NINSD_OPTIONS="'
   echo ninsd will terminate immediatly if it is started
   echo 'via the start procedure (systemd, init,...)'
   } >/dev/tty
   while :
   do
      echo >/dev/tty
      echo -n "Enter ethernet interface for the local IPv6 network: " >/dev/tty
      read args
      if [ x"$args" = "xq" -o "$args" = "xQ" ]
      then
         exit 1
      fi
      if [ "$args" != "" ]
      then
         echo $args
         break;
      fi
   done
}


if [ -e /etc/sysconfig/ ]
then
    ARGS=`get_args`
    touch /etc/sysconfig/ninsd
    echo "NINSD_OPTIONS='-i $ARGS'" > /etc/sysconfig/ninsd
elif  [ -e /etc/default/ ]
then
    ARGS=`get_args`
    echo "NINSD_OPTIONS='-i $ARGS'" > /etc/default/ninsd
else
    echo Sorry your system is not supported
    exit 1
fi

exit 0
