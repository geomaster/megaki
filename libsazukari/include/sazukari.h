#ifndef __SAZUKARI_H__
#define __SAZUKARI_H__
#include "common.h"
#define SAZUKARI_MESSAGE_HARD_LIMIT     1048576
#define SAZUKARI_MIN_BUFFER_SENTINEL    128

/** Sazukari public declarations **/
typedef struct szkr_ctx_t szkr_ctx_t;

typedef struct szkr_srvkey_t {
  byte modulus [ MEGAKI_RSA_KEYBYTES ],
       exponent[ MEGAKI_RSA_EXPBYTES ];
} szkr_srvkey_t;

typedef enum szkr_err_t {
  szkr_err_none,
  szkr_err_unknown,
  szkr_err_incompatible_versions,
  szkr_err_service_unavailable,
  szkr_err_unknown_errcode,
  szkr_err_invalid_state,
  szkr_err_protocol,
  szkr_err_internal,
  szkr_err_io,
  szkr_err_rehandshake_needed,
  szkr_err_server_blacklisted,
  szkr_err_message_too_long
} szkr_err_t;

typedef slength_t (* szkr_write_cb)(byte*, length_t, void*);

typedef slength_t (* szkr_read_cb)(byte*, length_t, void*);

typedef struct szkr_iostream_t {
  szkr_read_cb read_callback;
  szkr_write_cb write_callback;
  void* cb_param;
} szkr_iostream_t;

/** End Sazukari public declarations **/

/** Sazukari public API **/
int        szkr_init();
int        szkr_get_ctxsize();
int        szkr_new_ctx(szkr_ctx_t* ctx, szkr_iostream_t ios,
                        szkr_srvkey_t srvkey);
int        skzr_reset_ctx(szkr_ctx_t* ctx);
int        szkr_do_handshake(szkr_ctx_t* ctx);
szkr_err_t szkr_last_error(szkr_ctx_t* ctx);
int        szkr_send_message(szkr_ctx_t*, byte* msg, length_t msglen, 
                             byte* responsebuf, length_t* responselen);
void       szkr_destroy_ctx(szkr_ctx_t* ctx);
void       szkr_destroy();
/** End Sazukari public API **/

#endif // __SAZUKARI_H__
