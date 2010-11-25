all: twitsecret

twitsecret: main.c packer.c
	gcc -arch i386 -Wall `libgcrypt-config --cflags --libs` -lz -o twitsecret main.c packer.c

clean:
	-rm twitsecret
