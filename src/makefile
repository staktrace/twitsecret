all: twitsecret

twitsecret: main.c packer.c packer.h
	gcc -arch i386 -Wall `libgcrypt-config --cflags --libs` -lz -o twitsecret main.c packer.c

install: twitsecret
	mkdir -p ../ffext/backend/x86
	cp twitsecret ../ffext/backend/x86

clean:
	-rm twitsecret
