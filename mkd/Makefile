CC=gcc
CFLAGS=-DDEBUG -Iinclude -Wall -g
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

COMMONHEADERS = \
              common.h \
              megaki.h
              
COMMONSRC = \
              common.c
          
COMMONHEADERSPREF = $(addprefix ../common/include/,$(COMMONHEADERS))

COMMONSRCPREF = $(addprefix ../common/src/,$(COMMONSRC))

OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: bin/mkd

$(addprefix include/,$(COMMONHEADERS)): $(COMMONHEADERSPREF)
	cp $(COMMONHEADERSPREF) include/

$(addprefix src/,$(COMMONSRC)): $(COMMONSRCPREF)
	cp $(COMMONSRCPREF) src/
	
bin/mkd: $(OBJ)         
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	
obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o bin/mkd
	cd include && rm -f $(COMMONHEADERS)
	cd src && rm -f $(COMMONSRC)
