#ifndef __TOKEN_BANK_H__
#define __TOKEN_BANK_H__
#include "common.h"
#include "megaki.h"
#define TOKEN_PAYLOAD_BYTES             (MEGAKI_AES_KEYBYTES)

typedef struct tokentry {
  byte token[MEGAKI_TOKEN_BYTES];
  byte payload[TOKEN_PAYLOAD_BYTES];
} tokentry;

int tokinit(unsigned int maxtoks, unsigned int maxbuckets);
tokentry* tok_create(byte* token);
void tok_renew(tokentry* entry);
tokentry* tok_find(byte* token);
void tokshutdown();

#endif
