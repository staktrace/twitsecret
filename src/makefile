all: twitsecret

twitsecret: main.c packer.c packer.h
	gcc -arch i386 -Wall `libgcrypt-config --cflags --libs` -lz -o twitsecret main.c packer.c

clean:
	-rm twitsecret
