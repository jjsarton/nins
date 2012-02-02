DEFINES=
LDLIBS=
ADDLIB=

CC=gcc
CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall
CFLAGS=$(CCOPT) $(GLIBCFIX) $(DEFINES) 

all: radvc

radvc: radvc.c

clean:
	@+rm radvc

install: radvc install-sbin install-man install-start

install-sbin: /usr/sbin/ 
	@cp radvc /usr/sbin

install-man: /usr/share/man/man8/
	@gzip -c radvc.8 > /usr/share/man/man8/radvc.8.gz

install-start:
	@if [ -e /lib/systemd/system/ ]; then \
	        make install-systemd;\
	else \
	        make install-init;\
	fi

install-systemd:
	@cp radvc.service /lib/systemd/system/radvc.service
	@systemctl enable radvc.service
	@systemctl start radvc.service

install-init:
	@cp radvc.sh /etc/init.d/radvc
	@chmod a+x /etc/init.d/radvc
	@/etc/init.d/radvc start
	@if [ -e /etc/rc5.d ]; then \
	         ln -s ../init.d/radvc /etc/rc5.d/S10radvc; \
	fi

uninstall: uninstall-sbin uninstall-man uninstall-start

uninstall-sbin: /usr/sbin/radvc
	@+rm -f /usr/sbin/radvc
	@make clean

uninstall-man: /usr/share/man/man8/radvc.8.gz
	@+rm -f /usr/share/man/man8/radvc.8.gz

uninstall-start:
	@if [ -e /lib/systemd/system/ ]; then \
	        make uninstall-systemd;\
	else \
	        make uninstall-init;\
	fi

uninstall-systemd: /lib/systemd/system/radvc.service
	@systemctl stop radvc.service
	@systemctl disable radvc.service
	@rm /lib/systemd/system/radvc.service
	@systemctl daemon-reload

uninstall-init:
	@+/etc/init.d/radvc stop
	@if [ -e /etc/rc5.d/S10radvc ]; then \
	        rm -f /etc/rc5.d/S10radvc;\
	fi
	@+rm -f /etc/init.d/radvc

/usr/sbin/radvc: radvc
/usr/share/man/man8/radvc.8.gz: radvc.8
/lib/systemd/system/radvc.service: radvc.service

