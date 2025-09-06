CC=gcc
CFLAGS=-Wall -Wextra -O2 -fPIC -I./include
LDFLAGS=-ldl -lcrypto

all: loader modules/enc.so modules/dec.so

loader: src/loader.c include/module_api.h
	$(CC) $(CFLAGS) -o loader src/loader.c $(LDFLAGS)

modules/enc.so: modules/enc_mod.c include/module_api.h
	$(CC) $(CFLAGS) -shared -o modules/enc.so modules/enc_mod.c -lcrypto

modules/dec.so: modules/dec_mod.c include/module_api.h
	$(CC) $(CFLAGS) -shared -o modules/dec.so modules/dec_mod.c -lcrypto

clean:
	rm -f loader modules/*.so
