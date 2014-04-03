#include "client.h"
#include "common.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>
#define MAGIC_BYTES       6
#define RSA_LIMIT         (MEGAKI_RSA_KEYSIZE / 8 - 42)

byte synbuf[2 * MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES];

/**
 * (Assuming RSA keysize of 2048b and tokensize of 128b.)
 * 
 * SYN packet:
 * 
 *    6B        32B                 256B                                 256B
 * [ header ] [ hash ] [ RSA server-key encrypted block ] [ RSA server-key encrypted block ]
 *
 * Second block plaintext (of RSA_LIMIT) is an xor of the first block
 * plaintext and the second block plaintext. When both are decrypted and 
 * decoded (second ^= first), they make up a data structure of exactly 262B:
 * 
 *              256B                       4B              2B
 * [        client key modulus       ] [ exponent ] [ version info ]
 * 
 * The hash is a SHA-2 hash of the recovered data structure.
 * 
 * SYN-ACK/SYN-ACK-ERR packet:
 * 
 *     6B       32B       16B                  256B
 * [ header ] [ hash ] [ token ] [ RSA client-key encrypted block ]
 * 
 * When decrypted with the client's one-time private key, the encrypted block
 * contains a data structure of exactly 48B:
 * 
 *    16B             32B
 * [ token ] [ server symmetric key ]
 * 
 * Alternatively, a SYN-ACK packet is a SYN-ACK-ERR packet and then the token 
 * within this encrypted block will be a special value of 16 0xEE bytes, followed
 * by an error code 32B long.
 * 
 * The hash is a SHA-2 hash of the recovered data structure.
 * 
 * ACK packet:
 * 
 *     6B        32B      16B       16B               16 * 3 = 48B
 * [ header ] [ hash ] [ token ] [  IV  ] [ AES server-key encrypted block * 2 ]
 * 
 * When decrypted with the AES server key previously sent to the client, and
 * the IV present in the message, the encrypted blocks contain a data
 * structure of exactly 48B:
 * 
 *    16B             32B
 * [ token ] [ client symmetric key ]
 * 
 * The hash is the SHA-2 hash of this data structure.
 * 
 * Upon the receival of the ACK packet, the server decrypts this block and
 * devises the master symmetric key from both server and client keys. All further
 * communication is done via mgk_*crypt_message routines.
 * 
 * MSG packet:
 * 
 *     6B       32B     16B     16B        4B           n * 16B
 * [ header ] [ MAC ] [ IV ] [ token ] [ length ] [ encrypted blocks ]
 * 
 * When decrypted, the encrypted blocks contain the token followed by a
 * 4-byte unique message identifier, followed by the raw data of specified
 * length.
 * 
 * The MAC is the HMAC-SHA256 of the ciphertext, with the secret of the master
 * symmetric key.
 *
 * RESTART-ACK packet:
 * 
 *     6B       32B      16B       32B           16B * 3 = 48B
 * [ header ] [ hash ] [ token ] [  IV  ] [ AES master-key encrypted block * 2 ]
 * 
 * This packet should restart a previous communication, based on the token.
 * The AES master-key encrypted blocks, when decrypted, contains a data 
 * structure of exactly 48B:
 *    
 *    16B               32B 
 * [ token ] [ AES client key augment ]
 * 
 * Upon receival of this packet, the server shall either acknowledge it
 * recognizes the token, derive the new, augmented master symmetric key
 * and associate it with the TCP connection or shall alternatively terminate
 * the pipe, in which case the client will reconnect and then renegotiate
 * a master key.
 * 
 * The hash is the SHA-2 hash of the decrypted data structure.
 * 
 * NOTE: All encrypted blocks contain the token first. This is for the lulz.
 * When I was writing this small spec I had a brainfart which led me to believe
 * that prepending the token to plaintexts improved security. Because a 16B
 * overhead is not much and the code is written, I'll leave it as it is. It
 * does no harm and may even provide a little obscurity as a last resort.
 * 
 * Added 12-3-14: Actually, I remembered that adding tokens allowed the system
 * to be safe against replay attacks (you can't replay a handshake as a new
 * token is generated every time) so it's a good idea I left it as is.
 * 
 * NOTE: If some kind of autherror occurs, no recovery attempt should be made and
 * the connection should be terminated promptly. If Megaki data is transferred
 * via TCP, which is most common, the only way autherrors could arise was if 
 * someone was deliberately tampering with the connection. It is important
 * that contexts be reinitialized: this is a lot of strain on the mobile processor
 * as new RSA primes need to be mined each time, but it is important that
 * no two connections share the same client key. Also, the client should stop
 * after some time of futile connections which should prevent a possible
 * attacker from draining the device's battery by repeatedly corrupting data
 * and forcing the client to reengage.
 * 
 * Megaki exhibits perfect forward secrecy by design.
 * 
 **/
struct mgk_serverauth {
  /* Server public key (n, e) */
  byte modulus[MEGAKI_RSA_KEYSIZE / 8];
  int32_t exponent;
};

struct mgk_clientctx {
  RSA *my_private, *server_public;
  byte server_symmetric[MEGAKI_AES_CBC_KEYSIZE / 8], master_symmetric[MEGAKI_AES_CBC_KEYSIZE / 8],
       session_token[MEGAKI_TOKEN_BYTES], synack_error[MEGAKI_ERROR_CODE_BYTES];
  int  synack_error_occured;
  AES_KEY master_aes_enc, master_aes_dec;
};

int mgk_create_master_aes(mgk_clientctx*);

int mgk_rand_seed(const byte* buf, length_t count)
{
  RAND_seed(buf, (int)count);
  return(1);
}

int mgk_create_master_aes(mgk_clientctx* ctx)
{
  if (!AES_set_encrypt_key(ctx->master_symmetric, MEGAKI_AES_CBC_KEYSIZE / 8,
    &ctx->master_aes_enc)) return(0);
  if (!AES_set_decrypt_key(ctx->master_symmetric, MEGAKI_AES_CBC_KEYSIZE / 8,
    &ctx->master_aes_dec)) return(0);
    
  return(1);
}

int mgk_init_client_ctx(mgk_clientctx** ctx, const mgk_serverauth* srvauth)
{
  mgk_clientctx* pctx;
  *ctx = (mgk_clientctx*)malloc(sizeof(mgk_clientctx));
  pctx = *ctx;
  if (!*ctx) {
    free(*ctx);
    return(0);
  }
  
  pctx->server_public = RSA_new();
  if (!pctx->server_public) {
    free(pctx);
    return(0);
  }
  if (!(pctx->server_public->n = BN_bin2bn(srvauth->modulus, MEGAKI_RSA_KEYSIZE / 8, NULL))) {
    BN_free(pctx->server_public->n);
    RSA_free(pctx->server_public);
    free(pctx);
    return(0);
  }
  
  if (!(pctx->server_public->e = BN_new())) {
    BN_free(pctx->server_public->n);
    RSA_free(pctx->server_public);
    free(pctx);
    return(0);
  }
  
  if (!BN_set_word(pctx->server_public->e, (unsigned long)srvauth->exponent)) {
    BN_free(pctx->server_public->e);
    BN_free(pctx->server_public->n);
    RSA_free(pctx->server_public);
    free(*ctx);
    return(0);
  }
  
  pctx->my_private = RSA_new();
  if (!pctx->my_private) {
    BN_free(pctx->server_public->e);
    BN_free(pctx->server_public->n);
    RSA_free(pctx->server_public);
    free(pctx);
    return(0);
  }

  if (!RSA_generate_key_ex(pctx->my_private, MEGAKI_RSA_KEYSIZE, pctx->server_public->e, NULL)) {
    BN_free(pctx->server_public->e);
    BN_free(pctx->server_public->n);
    RSA_free(pctx->server_public);
    RSA_free(pctx->my_private);
    free(*ctx);
    return(0);
  }
  return(1);
}

int mgk_build_syn(mgk_clientctx* ctx, byte* buf, length_t* buf_len)
{
  byte* msg_start;
  length_t mod_len, exp_len;
  unsigned int i;
  if (*buf_len < MAGIC_BYTES + 2 * MEGAKI_RSA_KEYSIZE / 8)
    return(0);
    
  mgk_fill_magic(buf, magic_syn);
  buf += MAGIC_BYTES + MEGAKI_HASH_BYTES;
  msg_start = buf;
  mod_len = BN_num_bytes(ctx->my_private->n);
  exp_len = BN_num_bytes(ctx->my_private->e);
  
  assert(mod_len <= MEGAKI_RSA_KEYSIZE / 8);
  memset(synbuf, 0, MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES);
  if (!BN_bn2bin(ctx->my_private->n, synbuf)) return(0);
  assert(exp_len <= 4);
  if (!BN_bn2bin(ctx->my_private->e, synbuf + MEGAKI_RSA_KEYSIZE / 8 + 4 - exp_len)) return(0);
  memcpy(synbuf + MEGAKI_RSA_KEYSIZE / 8 + 4, MEGAKI_VERSION, MEGAKI_VERSION_BYTES);
  
  SHA256(synbuf, MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES, buf - MEGAKI_HASH_BYTES);
   
  if (RSA_public_encrypt(RSA_LIMIT, synbuf, msg_start, ctx->server_public, RSA_PKCS1_OAEP_PADDING) == -1)
    return(0);
  for (i = 0; i < RSA_LIMIT; ++i)
    synbuf[i + RSA_LIMIT] ^= synbuf[i];
  if (RSA_public_encrypt(MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES - RSA_LIMIT, synbuf + RSA_LIMIT,
    msg_start + MEGAKI_RSA_KEYSIZE / 8, ctx->server_public, RSA_PKCS1_OAEP_PADDING) == -1) return(0);
    
  *buf_len = MAGIC_BYTES + MEGAKI_HASH_BYTES + 2 * MEGAKI_RSA_KEYSIZE / 8;
  return(1);
}

int mgk_decode_synack(mgk_clientctx* ctx, const byte* buf, length_t buf_len)
{
  byte mac[MEGAKI_HASH_BYTES];
  const byte *pmac;
  if (buf_len < MAGIC_BYTES + MEGAKI_HASH_BYTES + MEGAKI_TOKEN_BYTES + MEGAKI_RSA_KEYSIZE / 8)
    return(0);
    
  if (mgk_check_magic(buf) != magic_synack) return(0);
  buf += MAGIC_BYTES;
  pmac = buf;
  memcpy(mac, buf, MEGAKI_HASH_BYTES);
  buf += MEGAKI_HASH_BYTES;
  /*
    BN_print_fp(stderr, ctx->my_private->);
  fprintf(stderr,"\n");
  BN_print_fp(stderr, ctx->my_private->e);
  fprintf(stderr,"\n");
  */
  if (RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buf + MEGAKI_TOKEN_BYTES, synbuf,
    ctx->my_private, RSA_PKCS1_OAEP_PADDING) < MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8) {
          fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));

    return(0);
  }
  SHA256(synbuf, MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8, mac);
  if (!mgk_memeql(mac, pmac, MEGAKI_HASH_BYTES))
    return(0);
    
  if (mgk_memeql(synbuf, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES)) {
    ctx->synack_error_occured = 1;
    memcpy(ctx->synack_error, synbuf + MEGAKI_TOKEN_BYTES, MEGAKI_ERROR_CODE_BYTES);
    return(1);
  }
  
  if (!mgk_memeql(synbuf, buf, MEGAKI_TOKEN_BYTES))
    return(0);
    
  memcpy(ctx->session_token, buf, MEGAKI_TOKEN_BYTES);
  memcpy(ctx->server_symmetric, synbuf + MEGAKI_TOKEN_BYTES, MEGAKI_AES_CBC_KEYSIZE / 8);
  int lal;
  printf("token: ");
  for(lal=0;lal<MEGAKI_TOKEN_BYTES;++lal){printf("%x ",ctx->session_token[lal]);}
  printf("\n");
    printf("srvsymm: ");
  for(lal=0;lal<MEGAKI_AES_CBC_KEYSIZE/8;++lal){printf("%x ",ctx->server_symmetric[lal]);}
  printf("\n");
  return(1);
}

int mgk_check_synack_error(mgk_clientctx* ctx, byte* error_code)
{
  if (ctx->synack_error_occured) {
    if (error_code) memcpy(error_code, ctx->synack_error, MEGAKI_ERROR_CODE_BYTES);
    return(1);
  } else return(0);
}

int mgk_build_ack(mgk_clientctx* ctx, byte* buf, length_t* buf_len)
{
  length_t blklen = MAGIC_BYTES + MEGAKI_TOKEN_BYTES + MEGAKI_HASH_BYTES + MEGAKI_AES_BLOCK_BYTES +
    AES_ENCRYPTED_SIZE(MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8);
  if (*buf_len < blklen)
    return(0);
  
  byte* pmac;
  mgk_fill_magic(buf, magic_ack);
  buf += MAGIC_BYTES;
  pmac = buf;
  buf += MEGAKI_HASH_BYTES;
  memcpy(buf, ctx->session_token, MEGAKI_TOKEN_BYTES);
  buf += MEGAKI_TOKEN_BYTES;
  
  AES_KEY fk;
  byte iv[MEGAKI_AES_BLOCK_BYTES], key[AES_ENCRYPTED_SIZE(MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8)];
  if (!RAND_bytes(iv, MEGAKI_AES_BLOCK_BYTES)) 
    return(0);
  
  if (!RAND_bytes(key + MEGAKI_TOKEN_BYTES, sizeof(key) - MEGAKI_TOKEN_BYTES))
    return(0);
    
  memcpy(buf, iv, MEGAKI_AES_BLOCK_BYTES);
  buf += MEGAKI_AES_BLOCK_BYTES;
  memcpy(key, ctx->session_token, MEGAKI_TOKEN_BYTES);
  
  if (AES_set_encrypt_key(ctx->server_symmetric, MEGAKI_AES_CBC_KEYSIZE, &fk) != 0)
    return (0);
  
  AES_cbc_encrypt(key, buf, sizeof(key), &fk, iv, AES_ENCRYPT);
  SHA256(key, sizeof(key), pmac);
  
  unsigned int i;
  for (i = 0; i < MEGAKI_AES_CBC_KEYSIZE / 8; ++i)
    ctx->master_symmetric[i] = key[MEGAKI_TOKEN_BYTES + i] ^ (~ctx->server_symmetric[i]);
    
    int lal;
    printf("mastersym: ");
  for(lal=0;lal<MEGAKI_AES_CBC_KEYSIZE/8;++lal){printf("%x ",ctx->master_symmetric[lal]);}
  printf("\n");
  if (!mgk_create_master_aes(ctx))
    return(0);
    
  *buf_len = blklen;
  return(1);
}

length_t mgk_get_encrypted_size(length_t cleartext_size)
{
  return MAGIC_BYTES + MEGAKI_TOKEN_BYTES + MEGAKI_AES_BLOCK_BYTES + MEGAKI_LENGTH_BYTES +
         MEGAKI_HASH_BYTES + AES_ENCRYPTED_SIZE(cleartext_size + MEGAKI_TOKEN_BYTES);
}

void mgk_destroy_client_ctx(mgk_clientctx** ctx)
{
  /*BN_free((*ctx)->server_public->n);
  BN_free((*ctx)->server_public->e);*/
  
  RSA_free((*ctx)->my_private);
  RSA_free((*ctx)->server_public);
  free(*ctx);
}
