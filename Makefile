COMMON_FILES=common/include/*.h common/src/*.c

default: all

all: mkd libsazukari

mkd: $(COMMON_FILES) mkd/src/*.c
	cd mkd && make

libsazukari: $(COMMON_FILES) libsazukari/src/*.c
	cd libsazukari && make

clean:
	cd mkd && make clean
	cd libsazukari && make clean

callgraph: docs/maskom-callgraph.gv

docs/maskom-callgraph.gv: mkd/obj/*.o libsazukari/obj/*.o
	cd mkd && make callgraph
	cd libsazukari && make callgraph
	egypt mkd/obj/*.expand libsazukari/obj/*.expand > docs/maskom-callgraph.gv

.PHONY: all clean
