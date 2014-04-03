CC=gcc
LD=gcc
CFLAGS=-c -fPIC -Wall -g
LIBS=-L/usr/local/lib -lcrypto -luv

default: all	

all: megaki tests

megaki: bin/libmegaki.so bin/megakitd

tests: bin/client-test

bin/megakitd: obj/server.o \
              obj/common.o \
              obj/threadpool.o \
              obj/tokenbank.o \
              obj/hexdump.o \
              obj/sslc.o \
              obj/yami.o
              
	$(LD) -obin/megakitd \
	       obj/server.o \
	       obj/common.o \
	       obj/tokenbank.o \ 
	       obj/threadpool.o \
	       obj/sslc.o \
	       obj/hexdump.o \
	       obj/yami.o \
	       -pthread \
	       $(LIBS)
  
bin/libmegaki.so: obj/client.o \
                  obj/common.o
	$(LD) -obin/libmegaki.so -shared \
	       obj/client.o \
	       obj/common.o \
	       $(LIBS)

bin/client-test: bin/libmegaki.so \
                 obj/client-test.o
	$(LD) -obin/client-test \
	       obj/client-test.o \
	       -Lbin \
	       -lmegaki \
	       -lcrypto
  
obj/server.o: src/server.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/server.o src/server.c
  
obj/client.o: src/client.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/client.o src/client.c
  
obj/common.o: src/common.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/common.o src/common.c

obj/threadpool.o: src/thpool.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/threadpool.o src/threadpool.c
	
obj/hexdump.o: src/hexdump.o
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/hexdump.o src/hexdump.c
	
obj/sslc.o: src/sslc.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/sslc.o src/sslc.c
	
obj/tokenbank.o: src/tokenbank.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/tokenbank.o src/tokenbank.c
	
obj/client-test.o: src/client-test.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/client-test.o src/client-test.c

obj/yami.o: src/yami.c
	$(CC) $(CFLAGS) $(CFLAGSE) -oobj/yami.o src/yami.c
	
clean:
	rm -rf obj/*.o
	rm -rf bin/client-test bin/megakitd bin/*.so
  	
.PHONY: clean
