LDFLAGS = -lwsock32 -lws2_32 -liphlpapi

all: wniqd.exe

wniqd.exe: wniqd.c
	$(CC) -o wniqd.exe wniqd.c $(LDFLAGS) $(CFLAGS)

clean:
	if cygrunsrv -L | grep wniqd; then cygrunsrv -R wniqd; fi
	rm *.exe

install-service: wniqd.exe
	cygrunsrv --install wniqd --path "`pwd`/wniqd.exe"
	cygrunsrv -S wniqd
