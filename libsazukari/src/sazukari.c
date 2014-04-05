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
int assemble_syn(szkr_ctx_t* ctx, byte* outbuf);
int handle_synack(szkr_ctx_t* ctx, byte* inbuf, length_t len);
int check_ackack(byte* buf, length_t len);
int assemble_ack(szkr_ctx_t* ctx, byte* outbuf);
int decode_msg(szkr_ctx_t* ctx, const byte* imsg, length_t len, byte* obuf, length_t *olen);
int assemble_msg(szkr_ctx_t* ctx, const byte* inmsg, byte* outresp, length_t* resplen);
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
  
  return(1);
}

szkr_err_t szkr_last_error(szkr_ctx_t* ctx)
{
  return( ctx->last_err );
}

int szkr_do_handshake(szkr_ctx_t* ctx)
{
  return(-1);
}

int szkr_redo_handshake(szkr_ctx_t* ctx)
{
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