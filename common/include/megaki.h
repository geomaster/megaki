#ifndef __MEGAKI_H__
#define __MEGAKI_H__
#include "common.h"
#include <openssl/aes.h>
#include <stdint.h>

/* - 42 because of PKCS#1-OAEP, see RSA_public_encrypt(3ssl) */
#define MEGAKI_RSA_BLOCK_BYTES            (MEGAKI_RSA_KEYBYTES - 42)

#define MEGAKI_AES_BLOCKCOUNT(B)          \
  (((B) + MEGAKI_AES_BLOCK_BYTES - 1) / (MEGAKI_AES_BLOCK_BYTES))
  
#define MEGAKI_AES_ENCSIZE(B)             \
  ((MEGAKI_AES_BLOCK_BYTES) * MEGAKI_AES_BLOCKCOUNT(B))

#define MEGAKI_RSA_BLOCKCOUNT(B)          \
  (((B) + MEGAKI_RSA_BLOCK_BYTES - 1) / (MEGAKI_RSA_BLOCK_BYTES))
  
#define MEGAKI_RSA_ENCSIZE(B)             \
  ((MEGAKI_RSA_KEYBYTES) * MEGAKI_RSA_BLOCKCOUNT(B))
  
#define pk __attribute__((__packed__))

extern const byte MEGAKI_VERSION[MEGAKI_VERSION_BYTES];
extern const byte MEGAKI_ERROR_TOKEN[MEGAKI_TOKEN_BYTES];
extern const byte MEGAKI_INCOMPATIBLE_VERSIONS_ERROR[MEGAKI_ERROR_CODE_BYTES];
extern const byte MEGAKI_SERVICE_UNAVAILABLE_ERROR[MEGAKI_ERROR_CODE_BYTES];
extern const byte MEGAKI_SERVER_BLACKLISTED_ERROR[MEGAKI_ERROR_CODE_BYTES];


/** Type of packet **/
typedef enum mgk_packet_type {
  magic_syn = 0x01,
  magic_synack = 0x02,
  magic_ack = 0x03,
  magic_msg = 0x04,
  magic_msg_err = 0xE4,
  magic_restart = 0x05,
  magic_ackack = 0x06
} mgk_magic_type;

/** Header of every packet **/
typedef struct pk mgk_header_t {
  byte              magic
                      [ MEGAKI_MAGIC_BYTES ];
  byte              type;
} mgk_header_t;

/** Hash type for MACs **/
typedef struct pk mgk_hash_t {
  byte              data
                      [ MEGAKI_HASH_BYTES ];
} mgk_hash_t;

/** Token type, connection identifier **/
typedef struct pk mgk_token_t {
  byte              data
                      [ MEGAKI_TOKEN_BYTES ];
} mgk_token_t;

/** Serialized RSA key **/
typedef struct pk mgk_rsa_key_t {
  byte              modulus
                      [ MEGAKI_RSA_KEYBYTES ];
  byte              exponent
                      [ MEGAKI_RSA_EXPBYTES ];  
} mgk_rsa_key_t;

/** Serialized AES key **/
typedef struct pk mgk_aes_key_t {
  byte              data
                      [ MEGAKI_AES_KEYBYTES ];
} mgk_aes_key_t;

/** One block of RSA data **/
typedef struct pk mgk_rsa_block_t {
  byte              data
                      [ MEGAKI_RSA_KEYBYTES ];
} mgk_rsa_block_t;

/** One block of AES data **/
typedef struct pk mgk_aes_block_t {
  byte              data
                      [ MEGAKI_AES_BLOCK_BYTES ];
} mgk_aes_block_t;

/** Plaintext of SYN ciphertext **/
typedef struct pk mgk_syn_plain_t {
  mgk_rsa_key_t     client_key;
  byte              version
                      [ MEGAKI_VERSION_BYTES ];
} mgk_syn_plain_t;

/** SYN packet **/
typedef struct pk mgk_syn_t {
  mgk_header_t      header;
  mgk_hash_t        hash;
  mgk_rsa_block_t   ciphertext
                    [ MEGAKI_RSA_BLOCKCOUNT(
                        sizeof(mgk_syn_plain_t)
                      ) 
                    ];
} mgk_syn_t;

/** Plaintext of SYNACK ciphertext **/
typedef struct pk mgk_synack_plain_t {
  mgk_token_t       token;
  mgk_aes_key_t     server_symmetric;
} mgk_synack_plain_t;

/** SYNACK packet **/
typedef struct pk mgk_synack_t {
  mgk_header_t      header;
  mgk_hash_t        hash;
  mgk_token_t       token;
  mgk_rsa_block_t   ciphertext
                    [ MEGAKI_RSA_BLOCKCOUNT(
                        sizeof(mgk_synack_plain_t)
                      )
                    ];
} mgk_synack_t;

/** ACK plaintext **/
typedef struct pk mgk_ack_plain_t {
  mgk_token_t       token;
  mgk_aes_key_t     client_symmetric;
} mgk_ack_plain_t;

/** ACK packet **/
typedef struct pk mgk_ack_t {
  mgk_header_t      header;
  mgk_hash_t        hash;
  mgk_token_t       token;
  mgk_aes_block_t   iv,
                    ciphertext
                    [ MEGAKI_AES_BLOCKCOUNT(
                        sizeof(mgk_ack_plain_t)
                      )
                    ];
} mgk_ack_t;

/** ACK-ACK packet **/
typedef struct pk mgk_ackack_t {
  mgk_header_t      header;
} mgk_ackack_t;

/** Message preamble **/
typedef struct pk mgk_msgpreamble_t {
  mgk_header_t      header;
  uint32_t          length;  
} mgk_msgpreamble_t;

/** Message header **/
typedef struct pk mgk_msghdr_t {
  mgk_msgpreamble_t preamble;
  mgk_token_t       token;
  mgk_hash_t        mac;
  mgk_aes_block_t   iv;
} mgk_msghdr_t;

int mgk_memeql(const byte*, const byte*, length_t);
int mgk_check_magic(const mgk_header_t* hdr);
void mgk_fill_magic(mgk_header_t* hdr);
void mgk_derive_master(const byte* srvsymm, const byte* clsymm,
    byte* mastersymm);
int mgk_encode_message(byte* msg, length_t msglen, 
    mgk_token_t token, const mgk_aes_key_t key, AES_KEY *schdkey,
    byte* res, length_t *reslen);
/* returns -1 on protocol error, -2 on internal failure: */
int mgk_decode_message(const byte* msg, length_t msglen, 
    mgk_token_t token, const mgk_aes_key_t key, AES_KEY *schdkey,
    byte* res, length_t *reslen);

/** End common definitions for Megaki protocol **/
#endif
