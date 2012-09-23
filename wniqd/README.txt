wniqd
-----

wniqd is a simple user space programm for windows
and implement partially RFC 4620. This programm is
intended to be used with ninsd which has to run on
a Linux system.

This version can be compiled with cygwin, minggw,
lcc or PellesC.
This version what compiled with cygwin, lcc and
PellesC under Windows XP SP3. Due to the absence
of other Windows systems, I what not able to test
this on Vista or Windows 7. 

wniqd shall be installed as a service and must run
with administrator privilege.

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

Build wniqd with mingw:
=======================
open the msys terminal, go to the directory
containing wniqd.c annd issue the command

make


Build wniqd with lcc:
=====================
Open a cmd window and go to the folder containing
wniqd.c.
Set the variable LCCROOT and PATH in order to be
able to build wniqd.exe and call make:

set LCCROOT="C:\lcc"
set PATH="%PATH%;%LCCROOT%/bin"
make -f Makefile.lcc

Remarks:
--------
We assume, here that lcc is installed under C:\lcc.
You may need to set LCCROOT to the correct path.


Build wniqd with PellesC:
=========================
Open the "Pelles C command Prompt" and go to the folder
containing wniqd.c. Then enter within the console:

pomake /F Makefile.pellesc

Remarks:
--------

The provided makefile (Makefile.pellesc) is for
a 32 bit system. If you have a 64 bits system you
should use the file Makefile.pellesc54 insteads of
the file Makefile.pellesc.


install wniqd.exe as service:
=============================
If you have build wniqd.exe with minggw, lcc or PellesC
you need a tool for running wniqd.exe as a serveice.

Such a tool can be found at http://nssm.cc/.
Download nssm-2.15.zip, extract the file and
got to the directory nssm-2.15\win32 or  nssm-2.15\win64
according to your system and run:

nssm.exe install

This command must be run as administrator, on Windows 7
you should open an administrator command and the run:

nssm.exe install

Fill the installer fields Application and Service name
and click Install service.

The last step ist to start the service with:

sc start <service>

where <service> is the Service name you have previouly
entered.

If sc is not installed on your system you can use
the graphical tools provided by your system.

Wniqd and Firewall
==================

The default Windows Firewall block first all messages
from the network and allowing all icmp frame to be
accepted is not sufficient, the message code used for
Node Information Queries are always blocked.
One solution constist to disable the firewal, this
may only be acceptable within a trusted environment.
The best solution is to install a third party firewall
as SoftPerfect PersonalFirewall (http://softperfect.com)
which allows a greater flexibility.

