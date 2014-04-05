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

/** Definitions of Sazukari objects **/
typedef struct szkr_ctx_t {
  mgk_token_t     token;
  mgk_aes_key_t   server_symmetric,
                  master_symmetric;
  RSA*            client_rsa;
  AES_KEY         kenc, kdec;
  szkr_iostream_t ios;
  szkr_err_t      last_err;
  
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

int szkr_new_ctx(szkr_ctx_t* ctx, szkr_iostream_t ios)
{
  ctx->state = state_inactive;
  ctx->ios = ios; 
  ctx->client_rsa = NULL;
  ctx->last_err = szkr_err_none;
  ctx->state = state_inactive;
  
  return(1);
}

int szkr_reset_ctx(szkr_ctx_t* ctx)
{
  szkr_iostream_t ios = ctx->ios;
  szkr_destroy_ctx(ctx);
  return( szkr_new_ctx(ctx, ios) );
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
    ctx->last_err = szkr_err_internal;
    goto failure;
  }
  
  if (!write_packet(&ctx->ios, (byte*) &pkts.syn, sizeof(mgk_syn_t))) {
    ctx->last_err = szkr_err_io;
    goto failure;
  }
  
  if (!read_packet(&ctx->ios, (byte*) &pkts.synack, sizeof(mgk_synack_t))) {
    ctx->last_err = szkr_err_io;
    goto failure;
  }
  
  if ((ret = handle_synack(ctx, &pkts.synack)) != szkr_err_none) {
    ctx->last_err = ret;
    goto failure;
  }
  
  if (assemble_ack(ctx, &pkts.ack) != 0) {
    ctx->last_err = szkr_err_internal;
    goto failure;
  }
  
  if (!write_packet(&ctx->ios, (byte*) &pkts.ack, sizeof(mgk_ack_t))) {
    ctx->last_err = szkr_err_io;
    goto failure;
  }
  
  if (!read_packet(&ctx->ios, (byte*) &pkts.ackack, sizeof(mgk_ackack_t))) {
    ctx->last_err = szkr_err_io;
    goto failure;
  }
  
  if (!check_ackack(&pkts.ackack)) {
    ctx->last_err = szkr_err_protocol;
    goto failure;
  }
  
  if (AES_set_encrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kenc) != 0) {
    ctx->last_err = szkr_err_internal;
    goto failure;
  }
  
  if (AES_set_decrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kdec) != 0) {
    ctx->last_err = szkr_err_internal;
    goto failure;
  }
  
  ctx->state = state_ready;
  return( 0 );
  
failure:
  ctx->state = state_error;
  return(-1);
}

int szkr_send_messge(szkr_ctx_t* ctx, const byte* msg, length_t msglen,
                     byte* responsebuf, length_t* responselen)
{
  return(-1);
}

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
/** End Sazukari internal functions definitions **/