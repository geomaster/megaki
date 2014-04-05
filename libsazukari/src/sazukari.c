#include "sazukari.h"
#include "megaki.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

/** Definitions of Sazukari objects **/
typedef struct szkr_ctx_t {
  mgk_token_t   token;
  mgk_aes_key_t server_symmetric,
                master_symmetric;
  RSA*          client_rsa;
  enum szkrctx_state {
    state_inactive,
    state_awaiting_synack,
    state_ready,
    state_awaiting_ackack,
    state_error
  }             state;
    
} szkr_ctx_t;
/** End definitions of Sazukari objects **/

/** Sazukari internal functions **/
int assemble_syn(szkr_resp_t* resp, szkr_ctx_t* ctx, byte* outbuf);
int handle_synack(szkr_resp_t* resp, szkr_ctx_t* ctx, byte* iobuf, length_t len);
int check_ackack(byte* buf, length_t len);
int assemble_ack(szkr_resp_t* resp, szkr_ctx_t* ctx, byte* outbuf);
int decode_msg(szkr_ctx_t* ctx, const byte* imsg, length_t len, byte* obuf, length_t *olen);
int assemble_msg(szkr_resp_t* resp, szkr_ctx_t* ctx, const byte* inmsg, byte* outresp, length_t* resplen);
/** End Sazukari internal functions **/

/** Sazukari public API **/
length_t szkr_get_ctx_size()
{
  return sizeof( szkr_ctx_t );
}

int szkr_bootstrap()
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();
  
  return(1);
}

int szkr_new_ctx(szkr_ctx_t* ctx)
{
  ctx->state = state_awaiting_synacks
  
  return(1);
}

szkr_resp_t szkr_incoming(szkr_ctx_t* ctx, byte* buffer, length_t len)
{
  szkr_resp_t res;
  res.status = szkr_status_ready;
  res.err_code = szkr_error_none;
  
  if (length < sizeof(mgk_header_t))
    goto failure;
  
  mgk_header_t* hdr = (mgk_header_t*) buffer;
  byte msgbuf[ SAZUKARI_MIN_BUFSIZE ];
  length_t buflen = SAZUKARI_MIN_BUFSIZE;
  
  switch (hdr->type) {
    case magic_synack:
      if (ctx->state == state_awaiting_synack)
        handle_synack(&res, ctx, buffer, len);
      else goto failure;
      
      break;
   
    case magic_msg:
      if (ctx->state == state_ready) {
        if (decode_msg(ctx, buffer, len, msgbuf, &buflen)) {
          memcpy(buffer, msgbuf, buflen);
          res.retlen_param.returned_message_length = buflen;
        } else {
          goto failure;
        }
      } else goto failure;
      
      break;
      
    default:
      goto failure;
  }
  
  return( res );
  
failure:
  ctx->state = state_error;
  res.status = szkr_status_error;
  return( res );
}

szkr_resp_t szkr_compile_message(szkr_ctx_t* ctx, const byte* msg, length_t msglen,
                                 byte* out_buffer, length_t buflen)
{
  
}

int szkr_reset_state(szkr_ctx_t* ctx)
{
  ctx->state = state_awaiting_synack;
  
  return(1);
}