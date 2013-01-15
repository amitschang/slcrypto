PREFIX=/usr/local
CC=gcc
CFLAGS=-shared -fPIC

default_target: build
build:
	$(CC) $(CFLAGS) crypto-module.c -lslang -lssl -o crypto-module.so
install:
	cp crypto-module.so $(PREFIX)/lib/slang/v2/modules
	cp crypto.sl $(PREFIX)/share/slsh/local-packages
	cp crypto.hlp $(PREFIX)/share/slsh/local-packages/help
clean:
	rm crypto-module.so
