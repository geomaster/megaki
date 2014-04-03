#ifndef __MEGAKI_COMMON_H__
#define __MEGAKI_COMMON_H__
#define MEGAKI_RSA_KEYSIZE                2048
#define MEGAKI_AES_CBC_KEYSIZE            256
#define MEGAKI_AES_BLOCK_BYTES            16
#define MEGAKI_TOKEN_BYTES                16
#define MEGAKI_ERROR_CODE_BYTES           32
#define MEGAKI_HASH_BYTES                 32
#define MEGAKI_VERSION_BYTES              2
#define MEGAKI_LENGTH_BYTES               4

#define AES_ENCRYPTED_SIZE(B)             ((MEGAKI_AES_BLOCK_BYTES) * (((B) + MEGAKI_AES_BLOCK_BYTES - 1) / (MEGAKI_AES_BLOCK_BYTES)))
//#define AES_ENCRYPTED_SIZE(B) (16*(B)/16)

#include <stdint.h>

typedef uint8_t byte;
typedef uint32_t length_t;

extern const byte MEGAKI_VERSION[MEGAKI_VERSION_BYTES];
extern const byte MEGAKI_ERROR_TOKEN[MEGAKI_TOKEN_BYTES];
extern const byte MEGAKI_INCOMPATIBLE_VERSIONS_ERROR[MEGAKI_ERROR_CODE_BYTES];
extern const byte MEGAKI_SERVICE_UNAVAILABLE_ERROR[MEGAKI_ERROR_CODE_BYTES];

typedef enum magic_type {
  magic_syn,
  magic_synack,
  magic_ack,
  magic_msg,
  magic_restart,
  magic_invalid
} magic_type;

void mgk_fill_magic(byte*, magic_type type);
magic_type mgk_check_magic(const byte *);
int mgk_memeql(const byte*, const byte*, length_t);

#endif
