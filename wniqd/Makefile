CC = gcc
LDFLAGS = -lwsock32  -lws2_32 -liphlpapi

all: wniqd.exe

wniqd.exe: wniqd.o
	$(CC) -o wniqd.exe wniqd.o $(LDFLAGS)

clean:
	if [ cygrunsrv -L | grep wniqd ]; \
	then \
		cygrunsrv -R wniqd; \
	fi
	rm *.exe *.o

install-service: wniqd.exe
	cygrunsrv --install wniqd --path "`pwd`/wniqd.exe"
	cygrunsrv -S wniqd
