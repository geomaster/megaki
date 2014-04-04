CC=gcc
CFLAGS=-O3 -DDEBUG -Iinclude -Wall -g
LIBS=-L/usr/local/lib -pthread -lcrypto -luv

OBJECTNAMES = \
              yugi.o \
              yami.o \
              pegasus.o \
              main.o \
              threadpool.o \
              common.o \
              tokenbank.o \
              sslc.o

HEADERNAMES = \
              yugi.h \
              yami.h \
              pegasus.h \
              threadpool.h \
              common.h \
              tokenbank.h \
              megaki.h \
              sslc.h

OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: bin/mkd

bin/mkd: $(OBJ)         
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	
obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o bin/mkd

