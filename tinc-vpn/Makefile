CFLAGS=-O2 -s -Wall
MANPATH=/usr/share/man/

all: set_route

set_route: set_route.c

clean:
	@if [ -f set_route ]; then rm -f set_route; fi

install: set_route
	@cp set_route /usr/bin
	@gzip -c set_route.8 > /usr/share/man/man8/et_route.8.gz

uininstall:
	@if [ -f /usr/bin/set_route ]; then rm -f /usr/bin/set_route; fi
	@if [ -f $(MANPATH)/man8/et_route.8.gz ]; then rm -f $(MANPATH)/man8/et_route.8.gz; fi
