CC=gcc
CFLAGS=-fdump-rtl-expand -O2 -DDEBUG -DYAMI_DIAGNOSTIC -Iinclude -Wall -g
LDFLAGS=
LIBS=-L/usr/local/lib -pthread -lcrypto -luv

OBJECTNAMES = \
              yugi.o \
              yami.o \
              pegasus.o \
              arcangelo.o \
              main.o \
              threadpool.o \
              common.o \
              tokenbank.o \
              sslc.o

HEADERNAMES = \
              yugi.h \
              yami.h \
              pegasus.h \
              arcangelo.h \
              threadpool.h \
              common.h \
              tokenbank.h \
              megaki.h \
              sslc.h \
              pmdk.h

COMMONHEADERS = \
              common.h \
              megaki.h
              
COMMONSRC = \
              common.c
          
COMMONHEADERSPREF = $(addprefix ../common/include/,$(COMMONHEADERS))

COMMONSRCPREF = $(addprefix ../common/src/,$(COMMONSRC))

OBJ=$(patsubst %,obj/%,$(OBJECTNAMES))
HEADERS=$(patsubst %,include/%,$(HEADERNAMES))

default: bin/mkd callgraph

$(addprefix include/,$(COMMONHEADERS)): $(COMMONHEADERSPREF)
	cp $(COMMONHEADERSPREF) include/

$(addprefix src/,$(COMMONSRC)): $(COMMONSRCPREF)
	cp $(COMMONSRCPREF) src/

callgraph: docs/mkd-callgraph.gv

docs/mkd-callgraph.gv: $(OBJ)
	egypt obj/*.expand > docs/mkd-callgraph.gv
	
bin/mkd: $(OBJ)         
	$(CC) $(LDFLAGS) -o $@ $^ $(CFLAGS) $(LIBS)
	
obj/%.o: src/%.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
.PHONY: clean

clean:
	rm -f obj/*.o obj/*.expand bin/mkd
	cd include && rm -f $(COMMONHEADERS)
	cd src && rm -f $(COMMONSRC)
