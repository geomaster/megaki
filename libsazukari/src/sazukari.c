#include "sazukari.h"
#include "megaki.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <assert.h>

#ifdef DEBUG
#define SAZUKARI_ASSERT(cond, s) \
  assert((cond) && (s))
#else
#define SAZUKARI_ASSERT(cond, s)
#endif

#undef min
#define min(a, b) ((a) < (b) ? (a) : (b))

/** Definitions of Sazukari objects **/
typedef struct szkr_ctx_t {
  mgk_token_t     token;
  mgk_aes_key_t   server_symmetric,
                  master_symmetric;
  RSA             *client_rsa,
                  *server_rsa;
  AES_KEY         kenc, kdec;
  szkr_iostream_t ios;
  szkr_err_t      last_err;
  szkr_srvkey_t   srvkey;
  
  enum szkrctx_state {
    state_inactive,
    state_error,
    state_ready
  } state;
} szkr_ctx_t;
/** End definitions of Sazukari objects **/

/** Sazukari internal functions **/
int        assemble_syn(szkr_ctx_t* ctx, mgk_syn_t* osyn);
szkr_err_t handle_synack(szkr_ctx_t* ctx, mgk_synack_t* isynack);
int        check_ackack(mgk_ackack_t* iackack);
int        assemble_ack(szkr_ctx_t* ctx, mgk_ack_t* oack);
szkr_err_t decode_msg(szkr_ctx_t* ctx, const byte* imsg, length_t len, byte* obuf, length_t *olen);
int        assemble_msg(szkr_ctx_t* ctx, const byte* inmsg, byte* outresp, length_t* resplen);
int        read_packet(szkr_iostream_t* ios, byte* buffer, length_t packetlen);
int        write_packet(szkr_iostream_t* ios, byte* buffer, length_t packetlen);
int        rsa_keygen(szkr_ctx_t* ctx);
/** End Sazukari internal functions **/

/** Sazukari public API **/
int szkr_get_ctxsize()
{
  return sizeof( szkr_ctx_t );
}

int szkr_init()
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();
  
  return(1);
}

int szkr_new_ctx(szkr_ctx_t* ctx, szkr_iostream_t ios, szkr_srvkey_t srvkey)
{
  ctx->state = state_inactive;
  ctx->ios = ios; 
  ctx->client_rsa = NULL;
  ctx->last_err = szkr_err_none;
  ctx->state = state_inactive;
  ctx->srvkey = srvkey;
  
  return(1);
}

int szkr_reset_ctx(szkr_ctx_t* ctx)
{
  szkr_iostream_t ios = ctx->ios;
  szkr_srvkey_t srvkey = ctx->srvkey;
  szkr_destroy_ctx(ctx);
  return( szkr_new_ctx(ctx, ios, srvkey) );
}

szkr_err_t szkr_last_error(szkr_ctx_t* ctx)
{
  return( ctx->last_err );
}

int szkr_do_handshake(szkr_ctx_t* ctx)
{
  if (ctx->state != state_inactive) {
    ctx->last_err = szkr_err_invalid_state;
    goto failure;
  }
  
  if (!ctx->client_rsa) {
    if (rsa_keygen(ctx) != 0) {
      ctx->last_err = szkr_err_internal;
      goto failure;
    }
  }
  union {
    mgk_syn_t syn;
    mgk_synack_t synack;
    mgk_ack_t ack;
    mgk_ackack_t ackack;
  } pkts;
  szkr_err_t ret;
  
  if (assemble_syn(ctx, &pkts.syn) != 0) {
    goto internal_err;
  }
  
  if (!write_packet(&ctx->ios, (byte*) &pkts.syn, sizeof(mgk_syn_t))) {
    goto io_err;
  }
  
  if (!read_packet(&ctx->ios, (byte*) &pkts.synack, sizeof(mgk_synack_t))) {
    goto io_err;
  }
  
  if ((ret = handle_synack(ctx, &pkts.synack)) != szkr_err_none) {
    ctx->last_err = ret;
    goto failure;
  }
  
  if (assemble_ack(ctx, &pkts.ack) != 0) {
    goto internal_err;
  }
  
  if (!write_packet(&ctx->ios, (byte*) &pkts.ack, sizeof(mgk_ack_t))) {
    goto io_err;
  }
  
  if (!read_packet(&ctx->ios, (byte*) &pkts.ackack, sizeof(mgk_ackack_t))) {
    goto io_err;
  }
  
  if (!check_ackack(&pkts.ackack)) {
    goto proto_err;
  }
  
  if (AES_set_encrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kenc) != 0) {
    goto internal_err;
  }
  
  if (AES_set_decrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kdec) != 0) {
    goto internal_err;
  }
  
  ctx->state = state_ready;
  return( 0 );

io_err:
  ctx->last_err = szkr_err_io;
  goto failure;

internal_err:
  ctx->last_err = szkr_err_internal;
  goto failure;

proto_err:
  ctx->last_err = szkr_err_protocol;
  goto failure;

failure:
  ctx->state = state_error;
  return(-1);
}

int szkr_send_message(szkr_ctx_t* ctx, const byte* msg, length_t msglen,
                     byte* responsebuf, length_t* responselen)
{
  return(-1);
}
// Note to further self: please find all references to 'int' and 'slength_t' in
// this source code and see if they pose a security risk! I know what I'm saying.
// ( TODO )
void szkr_destroy_ctx(szkr_ctx_t* ctx)
{
  if (ctx->client_rsa)
    RSA_free(ctx->client_rsa);

}

void szkr_destroy()
{
  EVP_cleanup();
  ERR_free_strings();
}
/** End Sazukari public API **/

/** Sazukari internal functions definitions **/
int read_packet(szkr_iostream_t* ios, byte* buffer, length_t packetlen)
{
  length_t read = 0;
  slength_t this_read = 0;
  while (read < packetlen &&
         (this_read = ios->read_callback(buffer + read, packetlen - read, 
                                         ios->cb_param) > 0))
         
    read += this_read;
  
  return (read == packetlen);
}

int write_packet(szkr_iostream_t* ios, byte* buffer, length_t packetlen)
{
  return (ios->write_callback(buffer, packetlen, ios->cb_param) == packetlen);
}  

int rsa_keygen(szkr_ctx_t* ctx)
{
  ctx->server_rsa = RSA_new();
  if (!ctx->server_rsa)
    goto failure;
  
  if (!(ctx->server_rsa->n = BN_bin2bn(ctx->srvkey.modulus, MEGAKI_RSA_KEYBYTES,
                                      NULL)))
    goto destroy_srvrsa;

  if (!(ctx->server_rsa->e = BN_bin2bn(ctx->srvkey.exponent, MEGAKI_RSA_EXPBYTES,
                                      NULL)))
    goto destroy_srvmod;
  
  ctx->client_rsa = RSA_new();
  if (!ctx->client_rsa)
    goto destroy_srvexp;

  if (!RSA_generate_key_ex(ctx->client_rsa, MEGAKI_RSA_KEYSIZE, 
                           ctx->server_rsa->e, NULL)) 
    goto destroy_clrsa;
 
  return(0);
  
destroy_clrsa:
  RSA_free(ctx->client_rsa);
  
destroy_srvexp:
  BN_free(ctx->server_rsa->e);
  ctx->server_rsa->e = NULL;
  
destroy_srvmod:
  BN_free(ctx->server_rsa->n);
  ctx->server_rsa->n = NULL;
  
destroy_srvrsa:
  RSA_free(ctx->server_rsa);
  
failure:
  return(-1);
}

int assemble_syn(szkr_ctx_t* ctx, mgk_syn_t* osyn)
{
  mgk_fill_magic(&osyn->header);
  osyn->header.type = magic_syn;
  
  mgk_syn_plain_t synplain;
  SAZUKARI_ASSERT(BN_num_bytes(ctx->client_rsa->n) <= MEGAKI_RSA_KEYBYTES,
      "Not enough bytes to store the client RSA (n)");
  SAZUKARI_ASSERT(BN_num_bytes(ctx->client_rsa->e) <= MEGAKI_RSA_EXPBYTES,
      "Not enough bytes to store the client RSA (e)");

  if (BN_bn2bin(ctx->client_rsa->n, synplain.client_key.modulus + 
        (MEGAKI_RSA_KEYBYTES - BN_num_bytes(ctx->client_rsa->n))) <= 0) {
    goto failure;
  }

  if (BN_bn2bin(ctx->client_rsa->e, synplain.client_key.exponent +
        (MEGAKI_RSA_EXPBYTES - BN_num_bytes(ctx->client_rsa->e))) <= 0) {
    goto failure;
  }

  memcpy(synplain.version, MEGAKI_VERSION, MEGAKI_VERSION_BYTES);
  SHA256((unsigned char*) &synplain, sizeof(mgk_syn_plain_t), osyn->hash.data);
  byte* synplainb = (byte*) &synplain;

  int i, j;
  for (i = 1; i < MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_syn_plain_t)); ++i) {
    int ct = min(MEGAKI_RSA_BLOCK_BYTES, sizeof(mgk_syn_plain_t) - i *
        MEGAKI_RSA_BLOCK_BYTES);

    for (j = 0; j < ct; ++j)
      synplainb[i * MEGAKI_RSA_BLOCK_BYTES + j] ^=
        synplainb[(i - 1) * MEGAKI_RSA_BLOCK_BYTES + j];
  }

  for (i = 0; i < MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_syn_plain_t)); ++i)
    if (RSA_public_encrypt(
          min(sizeof(mgk_syn_plain_t) - i * MEGAKI_RSA_BLOCK_BYTES, 
            MEGAKI_RSA_BLOCK_BYTES),
          synplainb + i * MEGAKI_RSA_BLOCK_BYTES,
          (unsigned char*) &osyn->ciphertext[i].data,
          ctx->server_rsa,
          RSA_PKCS1_OAEP_PADDING) == -1) {
      goto failure;
  }

  return( 0 );

failure:
  return( -1 );
}

szkr_err_t handle_synack(szkr_ctx_t* ctx, mgk_synack_t* isynack)
{
  return (szkr_err_unknown);
}

int check_ackack(mgk_ackack_t* iackack)
{
  return( 0 );
}

int assemble_ack(szkr_ctx_t* ctx, mgk_ack_t* oack)
{
  return( -1 );
}
/** End Sazukari internal functions definitions **/
