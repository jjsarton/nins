LDFLAGS = -lwsock32 -lws2_32 -liphlpapi

all: wniqd.exe

wniqd.exe: wniqd.c
	$(CC) -o wniqd.exe wniqd.c $(LDFLAGS) $(CFLAGS)

clean:
	rm *.exe *.obj

install-service: wniqd.exe
	cygrunsrv --install wniqd --path "`pwd`/wniqd.exe"
	cygrunsrv -S wniqd

uninstall-service: wniqd.exe
	cygrunsrv -R wniqd
