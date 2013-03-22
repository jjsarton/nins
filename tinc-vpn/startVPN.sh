#!/bin/sh
# Please set the correct netname, see tinc documantation
NETNAME=home

SU_COMMAND=
PROTECTED=yes

# no graphical tool, you must set one of
######################################
SU_COMMAND=su
#SU_COMMAND=sudo

# Graphical command will be detected
#####################################
# fedora example: beesu ls -l
# SU_COMMAND=beesu

# openSuse example_ gnomesu -c "ls -l"
# SU_COMMAND="gnomesu -c"

# ubuntu
# SU_COMMAND=gksu

# KDE Desktop
# SU_COMMAND="kdesu -c"

start()
{
   # get interface name
   iface=`grep -i interface /etc/tinc/$1/tinc.conf| tr '=' ' '`
   if [ ! -n "$iface" ]
   then
      iface=$1
   else
      iface=`echo $iface | awk '{ print $NF }'`
   fi

   # create a persistent tap device
   if ! ip link sh dev $iface >/dev/null 2>/dev/null
   then
      ip tuntap add mode tap dev $iface
   fi

   # start vpn
   tincd -n $1
}

stop()
{
   tincd -k -n $1
}

case $1 in
start)start  $NETNAME; exit;;
stop) stop $NETNAME; exit;;
esac

ans=`zenity  --list  --text "Start / Stop $NETNAME VPN" \
    --radiolist  --column "Choose" --column "" TRUE Start FALSE Stop`


# Search graphical command
for cmd in beesu gnomesu gksu
do
    tmp=`which $cmd`
    if [ $? -eq 0 ]
    then
        command=`basename $tmp`
        break;
    fi
done

# if not found set the default
if [ ! -n $command ]
then
    command=$SU_COMMAND
fi

# set args if required and for sudo tell that the
# args may not be protected
case $command in
    beesu)   SU_COMMAND=beesu ;;
    gksu)    SU_COMMAND=gksu ;;
    gnomesu) SU_COMMAND="gnomesu -c" ;;
    kdesu)   SU_COMMAND="kdesu -c" ;;
    su)      SU_COMMAND="su root -c" ;;
    sudo)    SU_COMMAND="sudo -u root"; PROTECTED=no ;;
esac

# call us again with arguments via the root password utility
case $PROTECTED in
no)
    case $ans in
    Start)  $SU_COMMAND $0 start home ;;
    Stop)   $SU_COMMAND $0 stop home ;;
    esac
    ;;
yes)
    case $ans in
    Start)  $SU_COMMAND "$0 start home" ;;
    Stop)   $SU_COMMAND "$0 stop home" ;;
    esac
    ;;
esac
