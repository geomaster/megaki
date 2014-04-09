#include "common.h"
#include "megaki.h"
#include <string.h>

const byte MEGAKI_MAGIC[] = { 'M', 'G', 'K', 0xEA, 0xCA };

const byte MEGAKI_VERSION[] = { 0x0A, 0xFF };

const byte MEGAKI_ERROR_TOKEN[] = 
  { 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE };
  
const byte MEGAKI_INCOMPATIBLE_VERSIONS_ERROR[] = 
  { 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };
    
const byte MEGAKI_SERVICE_UNAVAILABLE_ERROR[] = 
  { 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };
    
const byte MEGAKI_BLACKLIST_SERVER_ERROR[] =
  { 0x03, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };
    
int mgk_memeql(const byte* a, const byte* b, length_t count)
{
  int result = 0;
  unsigned int i;
  for (i = 0; i < count; ++i)
    result |= a[i] ^ b[i];

  return(!result);
}

int mgk_check_magic(const mgk_header_t* hdr)
{
  return mgk_memeql(hdr->magic, MEGAKI_MAGIC, MEGAKI_MAGIC_BYTES);
}

void mgk_fill_magic(mgk_header_t* hdr)
{
  memcpy(hdr->magic, MEGAKI_MAGIC, MEGAKI_MAGIC_BYTES); 
}

void mgk_derive_master(const byte* srvsymm, const byte* clsymm, byte* mastersymm)
{
  int i;
  for (i = 0; i < MEGAKI_AES_KEYBYTES; ++i)
    mastersymm[i] = (~srvsymm[i]) ^ clsymm[i];
}