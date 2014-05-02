callgraph: docs/maskom-callgraph.gv

docs/maskom-callgraph.gv: mkd/obj/*.o libsazukari/obj/*.o
	cd mkd && make callgraph
	cd libsazukari && make callgraph
	egypt mkd/obj/*.expand libsazukari/obj/*.expand > docs/maskom-callgraph.gv
