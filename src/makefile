all: twitsecret

twitsecret: main.c
	gcc -arch i386 -Wall `libgcrypt-config --cflags --libs` -o twitsecret main.c

clean:
	-rm twitsecret
