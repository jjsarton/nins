all:
	@cd ninsd; make;\
	cd ..;\
	cd radvc; make;

clean:
	@-cd ninsd; make clean;\
	cd ..;\
	cd radvc; make clean;

tgz: clean
	@cd ..;\
	tar czf nins.tgz nins
