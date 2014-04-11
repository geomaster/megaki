#include "yami.h"
#include "megaki.h"
#include "sslc.h"
#include "tokenbank.h"
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>

#define YAMI_VERSION_MAJOR              0
#define YAMI_VERSION_MINOR              1
#define YAMI_VERSION_REVISION           0
#define YAMI_VERSION_SUFFIX             "-privt"

#define YAMI_MAXTOKS                    10000
#define YAMI_MAXBUCKS                   20000

#undef min
#define min(a, b) ((a) < (b) ? (a) : (b))

#define YAMI_MAX_MESSAGE_LENGTH         \
  (MEGAKI_AES_BLOCK_BYTES * ((YAMI_MAX_PACKET_LENGTH - \
  sizeof(mgk_msghdr_t)) / MEGAKI_AES_BLOCK_BYTES))
  
#define YAMI_DIAGNOSTIC

/** Internal structures for MKD Yami **/
typedef struct yami_ctx_t {
  enum megaki_state {
    MGS_WAITING_SYN,
    MGS_RECEIVED_SYN,
    MGS_WAITING_ACK,
    MGS_TUNNEL_READY
  } state;
  
  union {
    struct {
      tokentry* token;
      mgk_aes_key_t server_symm;
    } synacks;
    
    struct {
      tokentry* token;
      AES_KEY kenc, kdec;
    } ackr;
  } x;
} yami_ctx_t;
/** End internal structures for MKD Yami **/

/** Debug macros **/
#ifdef YAMI_DEBUG
#include <assert.h>
#define YAMI_ASSERT(cond, msg) \
    assert((cond) && msg)
    
#ifdef YAMI_DIAGNOSTIC
#define YAMI_DIAGLOGS(s) \
    MEGAKI_LOGS(stderr, "YAMI", (s))
    
#define YAMI_DIAGLOGF(f, ...) \
    MEGAKI_LOGF(stderr, "YAMI", f, __VA_ARGS__)
#else
#define YAMI_DIAGLOGS(s)
#define YAMI_DIAGLOGF(f, ...)
#endif

#else
#define YAMI_ASSERT(cond, msg)
#define YAMI_DIAGLOGS(s)
#define YAMI_DIAGLOGF(f, ...)
#endif
/** End debug macros **/

/** Global variables **/
BN_CTX* yami__scbn;
RSA* yami__servercert;
char yami__version[100];
/** End global variables **/

/** Prototypes for internal procedures **/
void handle_syn(yami_ctx_t* ctx, yami_resp_t* resp, byte* buf);
void handle_synack(yami_ctx_t* ctx, yami_resp_t* resp, byte* buf);
void handle_ack(yami_ctx_t* ctx, yami_resp_t* resp, byte* buf);
int  assemble_synack(yami_ctx_t* ctx, RSA* clrsa, mgk_synack_t* res, const byte* err);
void handle_msg(yami_ctx_t* ctx, yami_resp_t* resp, byte* buf);
/** End prototypes for internal procedures **/

/** Yami public interface **/
void yami_version(int* major, int* minor, int* revision, char** suffix)
{
  *major = YAMI_VERSION_MAJOR;
  *minor = YAMI_VERSION_MINOR;
  *revision = YAMI_VERSION_REVISION;
  *suffix = YAMI_VERSION_SUFFIX;
}

const char* yami_strversion()
{
  int maj, min, rev;
  char* suff;
  yami_version(&maj, &min, &rev, &suff);
  snprintf(yami__version, 99, "%d.%d.%d%s", maj, min, rev, suff);
  return yami__version;  
}

int yami_getcontextsize() 
{
  return( sizeof(yami_ctx_t) );
}

int yami_init(yami_conf_t* config)
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();
  ssl_thread_setup();
  
  BIO* bio = BIO_new_mem_buf(config->certificate_buffer,
                             config->certificate_size);
  if (!bio)
    goto cleanup_ossl;
  
  PEM_read_bio_RSAPrivateKey(bio, &yami__servercert, NULL,
                             (void*)config->certificate_passphrase);
  if (!yami__servercert)
    goto cleanup_bio;
  
  if (BN_num_bytes(yami__servercert->n) < MEGAKI_RSA_KEYBYTES)
    goto cleanup_rsa;

  if (!tokinit(YAMI_MAXTOKS, YAMI_MAXBUCKS))
    goto cleanup_rsa;
  
  RAND_poll();
  if (config->random_file)
    if (RAND_load_file(config->random_file, config->random_bytes) < 
                       config->random_bytes)
      goto cleanup_rsa; 
    
  if (!RSA_blinding_on(yami__servercert, NULL)) {
    goto cleanup_rsa;
  }
  
  BIO_free(bio);
  return(0);
  
cleanup_rsa:
  RSA_free(yami__servercert);
  
cleanup_bio:
  BIO_free(bio);
  
cleanup_ossl:
  ssl_thread_cleanup();
  EVP_cleanup();
  ERR_free_strings();
  
  return(-1);
}

length_t yami_get_tunnel_headlen()
{
  return( sizeof(mgk_header_t) );
}

void yami_new_ctx(yami_ctx_t* ctx)
{
  ctx->state = MGS_WAITING_SYN;
}

yami_resp_t yami_incoming(yami_ctx_t* ctx, byte* buffer, length_t length)
{
  yami_resp_t resp;
  resp.data_size = 0;
  resp.tunneling_header_length = sizeof(mgk_header_t);
  
  mgk_header_t* hdr = (mgk_header_t*) buffer;
  if (!mgk_check_magic(hdr)) {
    YAMI_DIAGLOGS("Invalid magic");
    goto kill_connection;
  }
  
  switch (hdr->type) {
    case magic_syn:
      if (ctx->state == MGS_WAITING_SYN)
        handle_syn(ctx, &resp, buffer);
      else {
        YAMI_DIAGLOGS("Unexpected SYN packet");
        goto kill_connection;
      }
      
      break;
      
    case magic_ack:
      if (ctx->state == MGS_WAITING_ACK)
        handle_ack(ctx, &resp, buffer);
      else {
        YAMI_DIAGLOGS("Unexpected ACK packet");
        goto kill_connection;
      }
      
      break;
      
    case magic_msg:
      if (ctx->state == MGS_TUNNEL_READY)
        handle_msg(ctx, &resp, buffer);
      else {
        YAMI_DIAGLOGS("Unexpected MSG packet");
        goto kill_connection;
      }
      
      break;
      
    default:
      YAMI_DIAGLOGS("Unexpected packet type");
      goto kill_connection;
  };
  
  return(resp);
  
kill_connection:
  resp.end_connection = 1;
  return(resp);
}

int yami_get_packetlen(yami_ctx_t* ctx, byte* header, length_t* len)
{
  mgk_header_t* hdr = (mgk_header_t*) header;
  const mgk_msgpreamble_t* preamble; 
  switch (hdr->type) {
    case magic_syn:
      *len = sizeof(mgk_syn_t);
      return(1);
      
    case magic_ack:
      *len = sizeof(mgk_ack_t);
      return(1);
      
    case magic_msg:
      preamble = (mgk_msgpreamble_t*) header;
      if (!mgk_check_magic(&preamble->header) ||
          preamble->header.type != magic_msg) 
        return(0);
      
      uint32_t msglen = ntohl(preamble->length);
      if (msglen <= 0)
        return(0);
    
      /* expect full message header (incl. this preamble) and 
      * bytes announced */
      *len = sizeof(mgk_msghdr_t) + MEGAKI_AES_ENCSIZE(msglen);
      return(1);
  }
  return(0);
}

void yami_destroy()
{
  EVP_cleanup();
  ssl_thread_cleanup();
  RSA_blinding_off(yami__servercert);
  RSA_free(yami__servercert);
  ERR_free_strings();
  tokshutdown();
}

void yami_destroy_ctx(yami_ctx_t* ctx)
{
  
}

/** End Yami public interface **/

/** Yami internal procedures **/
void handle_syn(yami_ctx_t* ctx, yami_resp_t* resp, byte* buffer)
{
  resp->end_connection = 0;
  const mgk_syn_t* syn = (mgk_syn_t*) buffer;
  byte plainb[ MEGAKI_RSA_ENCSIZE(sizeof(mgk_syn_plain_t)) ];

  mgk_hash_t my_hash;
  const mgk_syn_plain_t *plain = (mgk_syn_plain_t*) plainb; 
  
  YAMI_DIAGLOGS("Handling SYN");
  
  int i, j, res, total = 0;
  for (i = 0; i < MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_syn_plain_t)); ++i)
    if ((res = RSA_private_decrypt(sizeof(mgk_rsa_block_t),
                            (unsigned char*) &syn->ciphertext[i].data, 
                            plainb + i * MEGAKI_RSA_BLOCK_BYTES,
                            yami__servercert,
                            RSA_PKCS1_OAEP_PADDING)) < 0) {
      YAMI_DIAGLOGF("Could not decrypt block %d of SYN data", i);
      goto kill_connection;
    } else total += res; 
  
  if (total != sizeof(mgk_syn_plain_t)) {
    YAMI_DIAGLOGS("Decrypted plaintext size erroneous");
    goto kill_connection;
  }

  for (i = 1; i < MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_syn_plain_t)); ++i) {
    int ct = min(MEGAKI_RSA_BLOCK_BYTES, sizeof(mgk_syn_plain_t) - i *
        MEGAKI_RSA_BLOCK_BYTES);

    for (j = 0; j < ct; ++j)
      plainb[i * MEGAKI_RSA_BLOCK_BYTES + j] ^=
        plainb[(i - 1) * MEGAKI_RSA_BLOCK_BYTES + j];
  }

  SHA256((unsigned char*) plain, sizeof(mgk_syn_plain_t), (unsigned char*) &my_hash.data);
  if (!mgk_memeql(my_hash.data, syn->hash.data, MEGAKI_HASH_BYTES)) {
    YAMI_DIAGLOGS("Invalid hash");
    goto kill_connection;
  }
  
  BIGNUM *modulus, *exponent;
  if (!(modulus = BN_bin2bn(plain->client_key.modulus,
                            MEGAKI_RSA_KEYBYTES, NULL))) {
    YAMI_DIAGLOGS("Internal error: could not convert bignum modulus");
    goto kill_connection;
  }
  
  if (!(exponent = BN_bin2bn(plain->client_key.exponent,
                            MEGAKI_RSA_EXPBYTES, NULL))) {
    YAMI_DIAGLOGS("Internal error: could not convert bignum exponent");
    goto destroy_modulus;
  }
  RSA* clrsa = RSA_new();
  if (!clrsa) {
   YAMI_DIAGLOGS("Internal error: could not create client RSA");
   goto destroy_exponent;
  }
  
  clrsa->n = modulus;
  clrsa->e = exponent;
  ctx->state = MGS_RECEIVED_SYN;
  
  if (!mgk_memeql(plain->version, MEGAKI_VERSION, MEGAKI_VERSION_BYTES)) {
    YAMI_DIAGLOGS("Mismatching versions, issuing SYN-ACK-ERR");
    if (assemble_synack(ctx, clrsa, (mgk_synack_t*) buffer,
                        MEGAKI_INCOMPATIBLE_VERSIONS_ERROR) != 0) {
      YAMI_DIAGLOGS("Could not assemble SYN-ACK-ERR");
    } else {
      resp->data_size = sizeof( mgk_synack_t );
    }
    goto destroy_rsa;
  }
  
  
  YAMI_DIAGLOGS("SYN ok");
  if (assemble_synack(ctx, clrsa, (mgk_synack_t*) buffer, NULL) != 0) {
    YAMI_DIAGLOGS("Failed to assemble SYN-ACK");
    goto destroy_rsa;
  } else {
    resp->data_size = sizeof( mgk_synack_t );
    ctx->state = MGS_WAITING_ACK;
  }
 
  RSA_free(clrsa);
  return ;
  
destroy_rsa:
  clrsa->n = NULL; /* so openssl doesn't double-free */
  clrsa->e = NULL;
  RSA_free(clrsa);
  
destroy_exponent:
  BN_free(exponent);
  
destroy_modulus:
  BN_free(modulus);
  
kill_connection:
  resp->end_connection = 1;
}

int assemble_synack(yami_ctx_t* ctx, RSA* clrsa, mgk_synack_t* res, const byte* err)
{
  mgk_synack_plain_t plain;
  if (!RAND_pseudo_bytes(plain.token.data, MEGAKI_TOKEN_BYTES)) {
    YAMI_DIAGLOGS("Internal error: failed to generate pseudo bytes for token");
    goto failure;
  }

  tokentry* tok;
  if (!err) {
    if (!RAND_bytes(plain.server_symmetric.data, MEGAKI_AES_KEYBYTES)) {
      YAMI_DIAGLOGS("Internal error: failed to generate random bytes for srvsymm");
      goto failure;
    }
    
    tok = tok_create(plain.token.data);
    if (!tok) {
      YAMI_DIAGLOGS("Internal error: failed to create a token in tokenbank");
      goto failure;
    }
    
    ctx->x.synacks.token = tok;
    memcpy(&ctx->x.synacks.server_symm, &plain.server_symmetric, sizeof(mgk_aes_key_t));
  }
  
  mgk_fill_magic(&res->header);
  res->header.type = magic_synack;
  memcpy(res->token.data, plain.token.data, MEGAKI_TOKEN_BYTES);
  
  if (err) {
    /* copy the error token and error code in place of real data */
    memcpy(plain.token.data, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES);
    memcpy(plain.server_symmetric.data, err, MEGAKI_ERROR_CODE_BYTES);
  }
  SHA256((void*) &plain, sizeof(mgk_synack_plain_t), res->hash.data);
  
  YAMI_ASSERT(MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_synack_plain_t)) == 1, 
              "No more than one block here is permitted");
  
  if (!RSA_blinding_on(clrsa, NULL)) {
    YAMI_DIAGLOGS("Internal error: could not turn on RSA blinding");
    goto failure;
  }
  
  if (RSA_public_encrypt(sizeof(mgk_synack_plain_t), (unsigned char*)&plain,
                         (unsigned char*)res->ciphertext[0].data, 
                         clrsa, RSA_PKCS1_OAEP_PADDING) < MEGAKI_RSA_KEYBYTES) {
    YAMI_DIAGLOGS("Could not encrypt with client public key");
    goto blind_off;
  }
  
  return(0);
  
blind_off:
  RSA_blinding_off(clrsa);
  
failure:
  return(-1);
}

void handle_ack(yami_ctx_t* ctx, yami_resp_t* resp, byte* buffer)
{
  const mgk_ack_t* ack = (mgk_ack_t*) buffer;
  union {
    byte plaind[ MEGAKI_AES_ENCSIZE(sizeof(mgk_ack_plain_t)) ];
    mgk_aes_key_t mastersymm;
  } x;
  mgk_hash_t hash;
  const mgk_ack_plain_t *plain = (mgk_ack_plain_t*) x.plaind;
  
  YAMI_DIAGLOGS("Handling ACK");
  
  if (!mgk_memeql(ack->token.data, ctx->x.synacks.token->token, MEGAKI_TOKEN_BYTES)) {
    YAMI_DIAGLOGS("Token mismatch");
    goto kill_connection;
  }
  
  AES_KEY srvdec;
  tokentry* tok = ctx->x.synacks.token;
  
  if (AES_set_decrypt_key(ctx->x.synacks.server_symm.data, MEGAKI_AES_KEYSIZE,
                          &srvdec) != 0) {
    YAMI_DIAGLOGS("Internal error: could not set AES decrypt key");
    goto kill_connection;
  }
  
  AES_cbc_encrypt((unsigned char*) ack->ciphertext, (unsigned char*) x.plaind,
                  MEGAKI_AES_ENCSIZE(sizeof(mgk_ack_plain_t)), &srvdec,
                  (unsigned char*)ack->iv.data, AES_DECRYPT);
  SHA256((unsigned char*) plain, sizeof(mgk_ack_plain_t),
         (unsigned char*)hash.data);
  if (!mgk_memeql(ack->hash.data, hash.data, MEGAKI_HASH_BYTES)) {
   YAMI_DIAGLOGS("Bad hash"); 
   goto kill_connection;
  }
  
  if (!mgk_memeql(ack->token.data, plain->token.data, MEGAKI_TOKEN_BYTES)) {
    YAMI_DIAGLOGS("Plaintext-ciphertext token mismatch");
    goto kill_connection;
  }
  
  mgk_derive_master(ctx->x.synacks.server_symm.data,
                    plain->client_symmetric.data, x.mastersymm.data);
  memcpy(tok->payload, x.mastersymm.data, MEGAKI_AES_KEYBYTES);
  ctx->x.ackr.token = tok;
  
  if (AES_set_encrypt_key((unsigned char*)&x.mastersymm, MEGAKI_AES_KEYSIZE, 
                           &ctx->x.ackr.kenc) != 0) {
    YAMI_DIAGLOGS("Internal error: could not set master AES encrypt key");
    goto kill_connection;
  }
  if (AES_set_decrypt_key((unsigned char*)&x.mastersymm, MEGAKI_AES_KEYSIZE, 
                           &ctx->x.ackr.kdec) != 0) {
    YAMI_DIAGLOGS("Internal error: could not set master AES decrypt key");
    goto kill_connection;
  }
  
  YAMI_DIAGLOGS("ACK ok");
  mgk_ackack_t *ackack = (mgk_ackack_t*) buffer;
  mgk_fill_magic(&ackack->header);
  ackack->header.type = magic_ackack;
  
  resp->data_size = sizeof(mgk_ackack_t);
  resp->tunneling_header_length = sizeof( mgk_msgpreamble_t );
  resp->end_connection = 0;
  ctx->state = MGS_TUNNEL_READY;
  
  return ;
  
kill_connection:
  resp->end_connection = 1;
}

void handle_msg(yami_ctx_t* ctx, yami_resp_t* resp, byte* buf)
{
  mgk_msghdr_t* hdr = (mgk_msghdr_t*) buf;
  uint32_t blkcount = MEGAKI_AES_BLOCKCOUNT(ntohl(hdr->preamble.length)),
           length = MEGAKI_AES_BLOCK_BYTES * blkcount;
  unsigned int ldummy;
  byte msg[ YAMI_MAX_MESSAGE_LENGTH ];

  mgk_aes_block_t* msg_contents = (mgk_aes_block_t*)(buf + 
        sizeof(mgk_msghdr_t)), hmac[ MEGAKI_HASH_BYTES ];
  
  YAMI_DIAGLOGS("Handling MSG");
  if (!mgk_memeql(ctx->x.synacks.token->token, hdr->token.data, MEGAKI_TOKEN_BYTES)) {
    YAMI_DIAGLOGS("Mismatching token");
    goto kill_connection;
  }
  
  if (!HMAC(EVP_sha256(), ctx->x.synacks.token->payload, MEGAKI_AES_KEYBYTES,
            (unsigned char*) msg_contents->data, length, (unsigned char*)
            hmac->data, &ldummy)) {
    YAMI_DIAGLOGS("Internal error: could not compute HMAC");
    goto kill_connection;
  }
  
  if (!mgk_memeql(hmac->data, hdr->mac.data, MEGAKI_HASH_BYTES)) {
    YAMI_DIAGLOGS("Wrong HMAC");
    goto kill_connection;
  }
  
  AES_cbc_encrypt((unsigned char*) msg_contents, (unsigned char*) msg,
                  length, &ctx->x.ackr.kdec, (unsigned char*) hdr->iv.data, 
                  AES_ENCRYPT);
  YAMI_DIAGLOGS("Decrypted message, TODO: Pegasus!");
  
  return ;
  
kill_connection:
  resp->end_connection = 1;
}
  
/** End Yami internal procedures **/
