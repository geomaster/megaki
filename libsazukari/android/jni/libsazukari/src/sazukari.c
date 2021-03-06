#include "sazukari.h"
#include "sslc.h"
#include "megaki.h"
#include <string.h>
#include <arpa/inet.h>
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
                  master_symmetric,
                  ephemeral,
                  client_augment;
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

typedef struct szkr_msg_t {
  mgk_msghdr_t    hdr;
  byte            data[ MEGAKI_AES_ENCSIZE(MEGAKI_MAX_MSGSIZE) ];
} szkr_msg_t;

typedef struct szkr_session_data_t {
  mgk_token_t     token;
  mgk_aes_key_t   master_key;
} szkr_session_data_t;

/** End definitions of Sazukari objects **/

/** Sazukari internal functions **/
int        assemble_syn(szkr_ctx_t* ctx, mgk_syn_t* osyn);
szkr_err_t handle_synack(szkr_ctx_t* ctx, mgk_synack_t* isynack);
int        check_ackack(mgk_ackack_t* iackack);
szkr_err_t handle_rstorack(szkr_ctx_t* ctx, szkr_session_data_t* data, byte* buf);
int        assemble_ack(szkr_ctx_t* ctx, mgk_ack_t* oack);
szkr_err_t decode_msg(szkr_ctx_t* ctx, const byte* imsg, length_t len, byte* obuf, length_t *olen);
int        assemble_msg(szkr_ctx_t* ctx, const byte* inmsg, byte* outresp, length_t* resplen);
int        assemble_rstor(szkr_ctx_t* ctx, szkr_session_data_t* data, byte* outbuf);
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
  ssl_thread_setup();
  
  return(0);
}

int szkr_new_ctx(szkr_ctx_t* ctx, szkr_iostream_t ios, szkr_srvkey_t srvkey)
{
  ctx->state = state_inactive;
  ctx->ios = ios; 
  ctx->client_rsa = NULL;
  ctx->last_err = szkr_err_none;
  ctx->state = state_inactive;
  ctx->srvkey = srvkey;

  return(0);
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
 
  ctx->last_err = szkr_err_none;
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

length_t szkr_get_session_data_size()
{
  return sizeof( szkr_session_data_t );
}

int szkr_get_session_data(szkr_ctx_t* ctx, byte* sdata, length_t* len)
{
  if (*len < sizeof(szkr_session_data_t))
    return( -1 );

  if (ctx->state != state_ready)
    return( -1 ); /* we haven't done a handshake! */

  szkr_session_data_t* data = (szkr_session_data_t*) sdata;
  memcpy(data->token.data, ctx->token.data, MEGAKI_TOKEN_BYTES);
  memcpy(data->master_key.data, ctx->master_symmetric.data, MEGAKI_AES_KEYBYTES);
  
  return( 0 );
}

int szkr_resume_session(szkr_ctx_t* ctx, const byte* sdata)
{
  szkr_err_t err = szkr_err_none;
  /* if (ctx->state != state_inactive) { */
  /*   err = szkr_err_invalid_state; */
  /*   goto failure; */
  /* } */

  szkr_session_data_t* data = (szkr_session_data_t*) sdata;
  byte msg[ MEGAKI_MSGSIZE(sizeof(mgk_msgrstor_plain_t)) ];
  if (assemble_rstor(ctx, data, msg) != 0) {
    err = szkr_err_internal;
    goto failure;
  }

  if (!write_packet(&ctx->ios, msg, MEGAKI_MSGSIZE(sizeof(mgk_msgrstor_plain_t)))) {
    err = szkr_err_io;
    goto failure;
  }
  
  SAZUKARI_ASSERT(MEGAKI_MSGSIZE(sizeof(mgk_msgrstorack_plain_t)) >= sizeof(mgk_rehandshake_req_t),
    "Not implemented as it does not make sense with Megaki as of now. Add support if needed.");
  
  byte ackmsg[ MEGAKI_MSGSIZE(sizeof(mgk_msgrstorack_plain_t)) ];

  /* read the header first, to decide our type of data */
  if (!read_packet(&ctx->ios, ackmsg, sizeof(mgk_header_t))) {
    err = szkr_err_io;
    goto failure;
  }

  mgk_magic_type incomingtype = ackmsg[offsetof(mgk_header_t, type)]; 
  if (!mgk_check_magic((mgk_header_t*) ackmsg)) {
    err = szkr_err_protocol;
    goto failure;
  }

  if (incomingtype == magic_req_rehs) {
    err = szkr_err_handshake_needed;
    goto failure;
  } else if (incomingtype != magic_msg_rstorack) {
    err = szkr_err_protocol;
    goto failure;
  }

  /* read the rest of the packet ... */
  if (!read_packet(&ctx->ios, ackmsg + sizeof(mgk_header_t), 
        MEGAKI_MSGSIZE(sizeof(mgk_msgrstorack_plain_t)) - sizeof(mgk_header_t))) {
    err = szkr_err_io;
    goto failure;
  }

  szkr_err_t ret;
  if ((ret = handle_rstorack(ctx, data, ackmsg)) != szkr_err_none) {
    err = ret;
    goto failure;
  }

  if (AES_set_encrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kenc) != 0) {
    err = szkr_err_internal;
    goto failure;
  }
  
  if (AES_set_decrypt_key(ctx->master_symmetric.data, MEGAKI_AES_KEYSIZE,
                          &ctx->kdec) != 0) {
    err = szkr_err_internal;
    goto failure;
  }
  /* byte response[ */
  ctx->last_err = szkr_err_none;
  ctx->state = state_ready;
  return( 0 );

failure:
  ctx->state = state_error;
  ctx->last_err = err;
  return( -1 );
}

int szkr_send_message(szkr_ctx_t* ctx, byte* msg, length_t msglen,
                     byte** responsebuf, length_t* responselen)
{
  szkr_err_t err;

  length_t encoded_len = MEGAKI_AES_ENCSIZE(msglen);
  if (msglen > SAZUKARI_MESSAGE_HARD_LIMIT) {
    err = szkr_err_message_too_long;
    goto failure;
  }

  RAND_pseudo_bytes(msg + msglen, encoded_len - msglen);

  length_t bufsize = MEGAKI_MSGSIZE(encoded_len);
  byte* outbuf = malloc(bufsize);
  if (!outbuf) {
    err = szkr_err_internal;
    goto failure;
  }

  if (mgk_encode_message(msg, msglen, ctx->token, ctx->master_symmetric, 
        &ctx->kenc, outbuf, &bufsize) != 0) {
    err = szkr_err_internal;
    goto dealloc_buffer;
  }

  if (!write_packet(&ctx->ios, outbuf, bufsize)) {
    err = szkr_err_io;
    goto dealloc_buffer;
  }

  mgk_msghdr_t hdr;
  if (!read_packet(&ctx->ios, (byte*) &hdr, sizeof(mgk_msghdr_t))) {
    err = szkr_err_io;
    goto dealloc_buffer;
  }

  if (!mgk_check_magic(&hdr.preamble.header)) {
    err = szkr_err_protocol;
    goto dealloc_buffer;
  }

  length_t inlen = ntohl(hdr.preamble.length);
  if (inlen > SAZUKARI_RESPONSE_HARD_LIMIT) {
    err = szkr_err_response_too_long;
    goto dealloc_buffer;
  }

  byte* respbuf = malloc(MEGAKI_AES_ENCSIZE(inlen) + 32 + MEGAKI_MSGSIZE(inlen));
  if (!respbuf) {
    err = szkr_err_internal;
    goto dealloc_buffer;
  }

  byte *resp_plainbuf = respbuf,
       *resp_fullbuf = respbuf + 32 + MEGAKI_AES_ENCSIZE(inlen);
  if (!read_packet(&ctx->ios, resp_fullbuf + sizeof(mgk_msghdr_t), MEGAKI_MSGSIZE(inlen) -
        sizeof(mgk_msghdr_t))) {
    err = szkr_err_io;
    goto dealloc_respbuffer;
  }

  memcpy(resp_fullbuf, &hdr, sizeof(mgk_msghdr_t));

  length_t outlen = MEGAKI_AES_ENCSIZE(inlen);
  int ret;
  if ((ret = mgk_decode_message(resp_fullbuf, MEGAKI_MSGSIZE(inlen), ctx->token, ctx->master_symmetric,
          &ctx->kdec, resp_plainbuf, &outlen)) != 0) {
    err = (ret == -1 ? szkr_err_protocol : szkr_err_internal);
    goto dealloc_respbuffer;
  }

  *responsebuf = resp_plainbuf; 
  *responselen = inlen;
  ctx->last_err = szkr_err_none;
  free(outbuf);
  return( 0 );

dealloc_respbuffer:
  free(respbuf);

dealloc_buffer:
  free(outbuf);

failure:
  ctx->last_err = err;
  return( -1 );
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
                                         ios->cb_param)) > 0)
         
    read += this_read;
  
  return (read == packetlen);
}

int write_packet(szkr_iostream_t* ios, byte* buffer, length_t packetlen)
{
  return (ios->write_callback(buffer, packetlen, ios->cb_param) == packetlen);
}  

int check_ackack(mgk_ackack_t* iackack)
{
  return( mgk_check_magic(&iackack->header) && 
          iackack->header.type == magic_ackack);
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
  memset(&synplain, 0, sizeof(mgk_syn_plain_t));

  SAZUKARI_ASSERT(BN_num_bytes(ctx->client_rsa->n) <= MEGAKI_RSA_KEYBYTES,
      "Not enough bytes to store the client RSA (n)");
  SAZUKARI_ASSERT(BN_num_bytes(ctx->client_rsa->e) <= MEGAKI_RSA_EXPBYTES,
      "Not enough bytes to store the client RSA (e)");

  if (!RAND_bytes((unsigned char*) synplain.eph_key.data, MEGAKI_AES_KEYBYTES)) {
    goto failure;
  }
  memcpy(ctx->ephemeral.data, synplain.eph_key.data, MEGAKI_AES_KEYBYTES);

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

szkr_err_t handle_rstorack(szkr_ctx_t* ctx, szkr_session_data_t* data, byte* buf)
{
  szkr_err_t res = szkr_err_unknown;
  mgk_msghdr_t* hdr = (mgk_msghdr_t*) buf;
  if (hdr->preamble.header.type != magic_msg_rstorack) {
    res = szkr_err_protocol;
    goto failure;
  }

  if (ntohl(hdr->preamble.length) != sizeof(mgk_msgrstorack_plain_t)) {
    res = szkr_err_protocol;
    goto failure;
  }

  mgk_aes_key_t augmentedkey;
  mgk_derive_master(data->master_key.data, ctx->client_augment.data, augmentedkey.data);

  AES_KEY kdec;
  if (AES_set_decrypt_key((unsigned char*) augmentedkey.data, MEGAKI_AES_KEYSIZE, &kdec) != 0) {
    res = szkr_err_internal;
    goto failure;
  }

  int ret;
  mgk_msgrstorack_plain_t rstorack_plain;
  length_t len = sizeof(rstorack_plain);
  if ((ret = mgk_decode_message(buf, MEGAKI_MSGSIZE(sizeof(mgk_msgrstorack_plain_t)), data->token,
        augmentedkey, &kdec, (byte*) &rstorack_plain, &len)) != 0) {
    res = (ret == -1 ? szkr_err_protocol : szkr_err_internal);
    goto failure;
  }
  mgk_derive_master(augmentedkey.data, rstorack_plain.server_key_augment.data, ctx->master_symmetric.data);

  return( szkr_err_none );
failure:
  return( res );
}

    
szkr_err_t handle_synack(szkr_ctx_t* ctx, mgk_synack_t* isynack)
{
  mgk_synack_plain_t plain;

  szkr_err_t res = szkr_err_unknown;

  if (!mgk_check_magic(&isynack->header))
    return( szkr_err_protocol );

  SAZUKARI_ASSERT(MEGAKI_RSA_BLOCKCOUNT(sizeof(mgk_synack_plain_t)) == 1,
      "This is not implemented as it is not possible without severe "
      "changes to the protocol. Please implement later if needed.");
  
  mgk_hash_t hmac;
  unsigned int ldummy = MEGAKI_HASH_BYTES;
  if (!HMAC(EVP_sha256(), (unsigned char*) ctx->ephemeral.data, MEGAKI_AES_KEYBYTES,
        (unsigned char*) isynack->ciphertext[0].data, MEGAKI_RSA_KEYBYTES, 
        (unsigned char*) hmac.data, &ldummy)) {
    return( szkr_err_internal );
  }

  if (!mgk_memeql(hmac.data, isynack->mac.data, MEGAKI_HASH_BYTES))
    return( szkr_err_protocol );

  if (!RSA_blinding_on(ctx->client_rsa, NULL))
    return( szkr_err_internal );

  if (RSA_private_decrypt(MEGAKI_RSA_KEYBYTES, (unsigned char*) isynack->ciphertext[0].data,
        (unsigned char*) &plain, ctx->client_rsa, RSA_PKCS1_OAEP_PADDING)
      != sizeof(mgk_synack_plain_t)) {
    res = szkr_err_protocol;
    goto blind_off;
  }

  if (mgk_memeql(isynack->token.data, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES)) {
    szkr_err_t err = szkr_err_unknown_errcode; 
    if (mgk_memeql(plain.token.data,
          MEGAKI_INCOMPATIBLE_VERSIONS_ERROR, MEGAKI_TOKEN_BYTES))
      err = szkr_err_incompatible_versions;
    else if (mgk_memeql(plain.token.data,
          MEGAKI_SERVICE_UNAVAILABLE_ERROR, MEGAKI_TOKEN_BYTES))
      err = szkr_err_service_unavailable;
    else if (mgk_memeql(plain.token.data,
          MEGAKI_SERVER_BLACKLISTED_ERROR, MEGAKI_TOKEN_BYTES))
      err = szkr_err_server_blacklisted;

    res = err;
    goto blind_off;
  } else {
    memcpy(ctx->server_symmetric.data, plain.server_symmetric.data, MEGAKI_AES_KEYBYTES);
    memcpy(ctx->token.data, plain.token.data, MEGAKI_TOKEN_BYTES);
    if (AES_set_encrypt_key((unsigned char*) plain.server_symmetric.data, 
          MEGAKI_AES_KEYSIZE, &ctx->kenc) != 0) {
      res = szkr_err_internal;
      goto blind_off;
    }
  }

  return( szkr_err_none );

blind_off:
  RSA_blinding_off(ctx->client_rsa);
  return( res );
}

int assemble_rstor(szkr_ctx_t* ctx, szkr_session_data_t* data, byte* outbuf)
{
  length_t encmsglen = MEGAKI_MSGSIZE(sizeof(mgk_msgrstor_plain_t));

  mgk_msgrstor_plain_t rmsg;
  if (!RAND_bytes((unsigned char*) rmsg.client_key_augment.data,
        MEGAKI_AES_KEYBYTES)) {
    goto failure;
  }

  AES_KEY aes_enc;
  if (AES_set_encrypt_key((unsigned char*) data->master_key.data,
        MEGAKI_AES_KEYSIZE, &aes_enc) != 0) {
    goto failure;
  }

  if (mgk_encode_message((byte*) &rmsg, sizeof(mgk_msgrstor_plain_t),
        data->token, data->master_key, &aes_enc, outbuf, &encmsglen) != 0) {
    goto failure;
  }
  ((mgk_msghdr_t*) outbuf)->preamble.header.type = magic_msg_rstor;
  memcpy(ctx->client_augment.data, rmsg.client_key_augment.data, MEGAKI_AES_KEYBYTES);
  return( 0 );

failure:
  return( -1 );

}

int assemble_ack(szkr_ctx_t* ctx, mgk_ack_t* oack)
{
  byte plainb[MEGAKI_AES_ENCSIZE(sizeof(mgk_ack_plain_t))];
  memset(plainb, 0, sizeof(plainb));

  mgk_ack_plain_t *plain = (mgk_ack_plain_t*) plainb;
  mgk_fill_magic(&oack->header);
  oack->header.type = magic_ack;

  mgk_aes_block_t iv;
  if (RAND_bytes((unsigned char*) plain->client_symmetric.data, 
        MEGAKI_AES_KEYBYTES) != 1)
    goto failure;
  
  if (RAND_bytes((unsigned char*) iv.data, MEGAKI_AES_BLOCK_BYTES) != 1)
    goto failure;

  static const slength_t leftover = MEGAKI_AES_ENCSIZE(sizeof(mgk_ack_plain_t)) - 
    sizeof(mgk_ack_plain_t);
  SAZUKARI_ASSERT(leftover >= 0, "Impossible condition!");

  if (leftover > 0) { /* known at compile time */
    /* pad with pseudo-randomness if there is leftover space */
    if (RAND_pseudo_bytes(plainb + sizeof(mgk_ack_t), leftover) < 0)
      return( -1 );
  }
  memcpy(oack->token.data, ctx->token.data, MEGAKI_TOKEN_BYTES);
  memcpy(plain->token.data, ctx->token.data, MEGAKI_TOKEN_BYTES);
  memcpy(oack->iv.data, iv.data, MEGAKI_AES_BLOCK_BYTES);

  /* This function mangles the IV passed to it, contrary to common sense. */
  AES_cbc_encrypt((unsigned char*) plainb, (unsigned char*) oack->ciphertext,
      sizeof(plainb), &ctx->kenc, (unsigned char*) iv.data, AES_ENCRYPT);
  memcpy(iv.data, oack->iv.data, MEGAKI_AES_BLOCK_BYTES);
  
  unsigned int ldummy = MEGAKI_HASH_BYTES;
  if (!HMAC(EVP_sha256(), ctx->ephemeral.data, MEGAKI_AES_KEYBYTES, 
        (unsigned char*) oack->iv.data, sizeof(plainb) + MEGAKI_AES_BLOCK_BYTES, 
        (unsigned char*) oack->mac.data, &ldummy)) {
    return( -1 );
  }

  memcpy(oack->iv.data, iv.data, MEGAKI_AES_BLOCK_BYTES);
  mgk_derive_master(ctx->server_symmetric.data, plain->client_symmetric.data,
      ctx->master_symmetric.data);

  return( 0 );

failure:
  return( -1 );
}
/** End Sazukari internal functions definitions **/
