CC=gcc
CFLAGS=-DDEBUG -Iinclude -shared -fPIC -Wall -g
TESTCFLAGS=-DTEST -DDEBUG -Iinclude -Lbin -Wall -g
LIBS=-lcrypto 
TESTLIBS=-lcrypto -lsazukari

OBJECTNAMES = \
              sazukari.o \
              common.o

TESTOBJNAMES = \
						  playground.o

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

TESTEXECS=$(patsubst %.o,tests/%,$(TESTOBJNAMES))
OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: sazukari tests

$(addprefix include/,$(COMMONHEADERS)): $(COMMONHEADERSPREF)
	cp $(COMMONHEADERSPREF) include/

$(addprefix src/,$(COMMONSRC)): $(COMMONSRCPREF)
	cp $(COMMONSRCPREF) src/
	
sazukari: bin/libsazukari.so

tests: bin/libsazukari.so $(TESTEXECS)

bin/libsazukari.so: $(OBJ)         
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

tests/%: tests/%.c bin/libsazukari.so
	$(CC) -o $@ $< $(TESTCFLAGS) $(TESTLIBS)

obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o bin/libsazukari.so
	cd include && rm -f $(COMMONHEADERS)
	cd src && rm -f $(COMMONSRC)

