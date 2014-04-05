CC=gcc
CFLAGS=-DDEBUG -Iinclude -shared -fPIC -Wall -g
LIBS=-lcrypto 

OBJECTNAMES = \
              sazukari.o \
              common.o

HEADERNAMES = \
              sazukari.h \
              common.h \
              megaki.h
              
OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: bin/libsazukari.so

bin/libsazukari.so: $(OBJ)         
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	
obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o bin/libsazukari.so

