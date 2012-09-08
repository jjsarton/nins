wniqd
-----

wniqd is a simple user space programm for windows
and implement paetially RFC 4620. This programm is
intended to be used with ninsd which has to run on
a Linux system.

This version can be compiled with cygwin, lcc or
PellesC.
This version what compiled with cygwin, lcc and
PellesC under Windows XP SP3. Due to the absence
of other Windows systems, I what not able to test
this on Vista or Windows 7. 

wniqd shall be installed as a service and must run
with administrator privilege.

Windows XP send router solicitation via multicast
addresses. Due to this, ninsd will not be able to
detect the presence of a new system. There are two
ways in order to get this working:

1) radvd can be configured for ignoring multicast
   solicitation ( flag UnicastOnly on )
2) ninsd can be instructed to periodically send
   a ping via multicast, the windows client will
   then respond to the icmp message and also send
   a beughbor advert. This can be enabled by the
   ninsd parameter "-e".

The most secure method is 2) but this implies
a lot of network traffic.

Build wniqd with Cygwin:
========================
Install cygwin and launch the "Cygwin Terminal"
and go to the directory where the wniqd source
are locates.
Type then make, the file wniqd will be compiled.

Installing wniqd as service:
----------------------------
Simply call "make install-service"

Deinstalling wniqd:
-------------------
open a  "Cygwin Terminal", go to the winqd directory
and type "make clean"


Build wniqd with lcc:
=====================
Open a cmd window and go to the folder containing
wniqd.c.
Set the variable LCCROOT and PATH in order to be
able to build wniqd.exe and call make:

set LCCROOT=C:\lcc
set PATH=%PATH%;%LCCROOT%/bin
make

Remarks:
--------
We assume, here that lcc is installed under C:\lcc.
You may need to set LCCROOT to the correct path.


Build wniqd with PellesC:
=========================
Open a cmd window and go to the folder containing
wniqd.c:

set PellesCDir=C:\Programs\PellesC
set PATH=%PATH%;%PellesCDir%\Bin
pomake -f Makefile.pellesc

Remarks:
--------
We assume, here that PellesC is installed under
C:\Programs\PellesC\.
You may need to set PellesCDir to the correct path.

The provided makefile (Makefile.pellesc) is for
a 32 bit system. For 64 bit systemes I don't know
if this is OK.


install wniqd.exe as service:
=============================
If you have build wniqd.exe with lcc or PellesC
you need a tool for running wniqd.exe as a serveice.

Such a tool can be found at http://nssm.cc/.
Download nssm-2.15.zip, extract the file and
got to the directory nssm-2.15\win32 or  nssm-2.15\win64
according to your system and run:

nssm.exe install

Fill the installer fields Application and Service name
and click Install service.

The last step ist to start the service with:

sc start <service>

where <service> is the Service name you have previouly
entered.

If sc is not installed on your system you can use
the graphical tools provided by your system.

