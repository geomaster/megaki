#ifndef __HEXDUMP_H__
#define __HEXDUMP_H__
#include <stdio.h>

void hexdump (FILE *f, char *desc, void *addr, int len);
#endif
