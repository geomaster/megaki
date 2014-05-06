#!/bin/sh
OPENSSL_ia32cap=~0x200000000000000 LD_PRELOAD=~/src/openssl-1.0.1g/libcrypto.so.1.0.0 valgrind bin/mkd
