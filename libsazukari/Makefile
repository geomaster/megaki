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
             
COMMONHEADERS = \
              common.h \
              megaki.h
              
COMMONSRC = \
              common.c
          
COMMONHEADERSPREF = $(addprefix ../common/include/,$(COMMONHEADERS))

COMMONSRCPREF = $(addprefix ../common/src/,$(COMMONSRC))

OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: bin/libsazukari.so

$(addprefix include/,$(COMMONHEADERS)): $(COMMONHEADERSPREF)
	cp $(COMMONHEADERSPREF) include/

$(addprefix src/,$(COMMONSRC)): $(COMMONSRCPREF)
	cp $(COMMONSRCPREF) src/
	
bin/libsazukari.so: $(OBJ)         
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
	
obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o bin/libsazukari.so
	cd include && rm -f $(COMMONHEADERS)
	cd src && rm -f $(COMMONSRC)

