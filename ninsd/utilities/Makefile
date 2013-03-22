CC=gcc
LDFLAGS=
CFLAGS=

all: getprefix calcsubnet

getprefix: getprefix.c
	@echo compile $@
	@$(CC) -o $@ $<

calcsubnet: calcsubnet.c
	@echo compile $@
	@$(CC) -o $@ $<

clean:
	@if [ -f getprefix ]; then rm getprefix; fi
	@if [ -f calcsubnet ]; then rm calcsubnet; fi
