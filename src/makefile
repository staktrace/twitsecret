all: twitsecret

twitsecret: main.c packer.c packer.h
	gcc -g -Wall -I../bin/gnupg-ecc/include/ -L../bin/gnupg-ecc/lib/ -lgcrypt -lgpg-error -lz -o twitsecret main.c packer.c

clean:
	-rm twitsecret
