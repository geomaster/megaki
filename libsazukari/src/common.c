#include "common.h"
#include "megaki.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <arpa/inet.h>
#include <string.h>

const byte MEGAKI_MAGIC[] = { 'M', 'G', 'K', 0xAA, 0xCA };

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
    
const byte MEGAKI_SERVER_BLACKLISTED_ERROR[] =
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

int mgk_encode_message(byte* msg, length_t msglen, 
    mgk_token_t token, const mgk_aes_key_t key, AES_KEY *schdkey,
    byte* res, length_t *reslen)
{
  mgk_msghdr_t hdr;
  int err = -2;
  mgk_fill_magic(&hdr.preamble.header);
  hdr.preamble.header.type = magic_msg;
  hdr.preamble.length = htonl(msglen);

  if (sizeof(mgk_msghdr_t) + MEGAKI_AES_ENCSIZE(msglen) > *reslen) {
    err = -1;
    goto failure;
  }

  if (RAND_bytes((unsigned char*) hdr.iv.data, MEGAKI_AES_BLOCK_BYTES) != 1) {
    err = -1;
    goto failure;
  }

  unsigned int ldummy;
  /* Because IVs are mangled by AES_cbc_encrypt */
  byte tmpiv[MEGAKI_AES_BLOCK_BYTES];
  memcpy(tmpiv, hdr.iv.data, MEGAKI_AES_BLOCK_BYTES);
  memcpy(hdr.token.data, token.data, MEGAKI_TOKEN_BYTES);

  AES_cbc_encrypt((unsigned char*) msg, (unsigned char*) res +
      sizeof(mgk_msghdr_t), MEGAKI_AES_ENCSIZE(msglen), schdkey, (unsigned char*) 
      (byte*) tmpiv, AES_ENCRYPT);
  memcpy(res + offsetof(mgk_msghdr_t, iv), hdr.iv.data, MEGAKI_AES_BLOCK_BYTES);

  if (!HMAC(EVP_sha256(), (unsigned char*) key.data, 
        MEGAKI_AES_KEYBYTES, (unsigned char*) res + offsetof(mgk_msghdr_t, iv), 
        MEGAKI_AES_ENCSIZE(msglen) + MEGAKI_AES_BLOCK_BYTES,
        (unsigned char*) hdr.mac.data, &ldummy)) {
    err = -1;
    goto failure;
  }
  memcpy(res, &hdr, sizeof(mgk_msghdr_t));
  *reslen = sizeof(mgk_msghdr_t) + MEGAKI_AES_ENCSIZE(msglen);

  return( 0 );

failure:
  return( err );

}

int mgk_decode_message(const byte* msg, length_t msglen, 
    mgk_token_t token, const mgk_aes_key_t key, AES_KEY *schdkey,
    byte* res, length_t *reslen)
{
  mgk_msghdr_t* hdr = (mgk_msghdr_t*) msg;
  uint32_t rllen = ntohl(hdr->preamble.length),
           blkcount = MEGAKI_AES_BLOCKCOUNT(rllen),
           length = MEGAKI_AES_BLOCK_BYTES * blkcount;
  unsigned int ldummy;

  if (length > *reslen)
    return( -3 );

  if (!mgk_check_magic(&hdr->preamble.header)) {
    goto proto_error;
  }

  if (sizeof(mgk_msghdr_t) + length != msglen) {
    goto proto_error;
  }

  mgk_aes_block_t* msg_contents = (mgk_aes_block_t*)(msg + 
        sizeof(mgk_msghdr_t)), hmac[ MEGAKI_HASH_BYTES ];
 
  if (!mgk_memeql(token.data, hdr->token.data, MEGAKI_TOKEN_BYTES)) {
    goto proto_error;
  }
  
  if (!HMAC(EVP_sha256(), key.data, MEGAKI_AES_KEYBYTES,
            (unsigned char*) hdr->iv.data, length + MEGAKI_AES_BLOCK_BYTES, 
            (unsigned char*) hmac->data, &ldummy)) {
    goto internal_error;
  }
  
  if (!mgk_memeql(hmac->data, hdr->mac.data, MEGAKI_HASH_BYTES)) {
    goto proto_error;
  }
  
  AES_cbc_encrypt((unsigned char*) msg_contents, (unsigned char*) res,
                  length, schdkey, (unsigned char*) hdr->iv.data, 
                  AES_DECRYPT);
  *reslen = rllen;

  return ( 0 );

proto_error:
  return( -1 );

internal_error:
  return( -3 );
}


