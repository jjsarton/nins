DEFINES=
LDLIBS=
ADDLIB=

CC=gcc
CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g
CFLAGS=$(CCOPT) $(GLIBCFIX) $(DEFINES) 

OBJECTS = ninsd.o list.o storage.o decode_ra.o open_socket.o send.o

all: ninsd update_hosts

update_hosts: update_hosts.c list.o
	@echo Link $@
	@cc -g -o update_hosts update_hosts.c list.o

ninsd: $(OBJECTS)
	@echo Link $@
	@cc -g -o ninsd $(OBJECTS)

clean:
	@+rm ninsd $(OBJECTS) update_hosts

ninsd.o: storage.h decode_ra.h  ninfo.h open_socket.h send.h
storage.o: storage.h list.h
decode_ra.o: decode_ra.h
open_socket.o: open_socket.h
send.o: send.h

install: install-config install-sbin install-start install-man

uninstall: uninstall-sbin uninstall-man uninstall-start uninstall-config

install-config:
	@./install-config.sh

install-sbin: ninsd
	@cp ninsd /usr/sbin/
	@make clean

install-start:
	@if [ -e /lib/systemd/system/ -a -e /bin/systemctl ]; then \
	        make install-systemd;\
	else \
	        make install-init;\
	fi
install-systemd:
	@make build_service_file
	@cp ninsd.service.temp /lib/systemd/system/ninsd.service
	@source /etc/*/ninsd; \
	if [ x"$$NINSD_IFACE" != x ]; then \
	    systemctl enable ninsd.service; \
	    systemctl start ninsd.service; \
	fi
	@rm -f ./ninsd.service.temp
build_service_file:
	@if [ -e /etc/sysconfig/ ]; then\
		cp ninsd.service ninsd.service.temp; \
	elif [ -e /etc/default/ ]; then \
		sed 's/sysconfig/default/' < ninsd.service > ninsd.service.temp; \
	fi

install-init:
	@cp ninsd.sh /etc/init.d/ninsd
	@chmod a+x /etc/init.d/ninsd
	@/etc/init.d/ninsd start
	@if [ -e /etc/rc5.d ]; then \
	         ln -s ../init.d/ninsd /etc/rc5.d/S20ninsd; \
	fi

install-man: /usr/share/man/man8/
	@+gzip -c ninsd.8 > /usr/share/man/man8/ninsd.8.gz


uninstall-sbin:
	@+rm -f ninsd /usr/sbin/ninsd

uninstall-man:
	@+rm -f /usr/share/man/man8/ninsd.8.gz

uninstall-start:
	@+if [ -e /lib/systemd/system/ -a -e /bin/systemctl ]; then \
	        make uninstall-systemd;\
	else \
	        make uninstall-init;\
	fi

uninstall-config:
	@+if [ -e /etc/sysconfig/niscd ]; then rm -f /etc/sysconfig/niscd; fi
	@+if [ -e /etc/default/niscd ]; then rm -f /etc/default/niscd; fi

uninstall-systemd:
	@+systemctl stop ninsd.service
	@+systemctl disable ninsd.service
	@+rm /lib/systemd/system/ninsd.service
	@+systemctl daemon-reload

uninstall-init:
	@+/etc/init.d/ninsd stop
	@if [ -e /etc/rc5.d/S20ninsd ]; then \
	        rm -f /etc/rc5.d/S20ninsd;\
	fi
	@+rm -f /etc/init.d/ninsd

.c.o:
	@echo Compile $<
	@$(CC) $(CFLAGS) -c -o $@ $<
