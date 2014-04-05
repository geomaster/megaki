#ifndef __SAZUKARI_H__
#define __SAZUKARI_H__
#include "common.h"
#define SAZUKARI_MIN_BUFSIZE            8448

/** Sazukari public declarations **/
enum szkr_error {
  szkr_error_none,
  szkr_error_unknown,
  szkr_incompatible_version,
  szkr_service_unavailable,
  szkr_blacklist_server,
  szkr_buffer_too_short
}

typedef struct szkr_ctx_t szkr_ctx_t;
typedef struct szkr_resp_t {
  union {
    /** Used if status is szkr_status_handshaking **/
    length_t new_expected_size;
    
    /** Used if status becomes szkr_status_ready **/
    length_t message_header_length;
  }          length_param;
  union {
    /** Used if status is szkr_status_handhsaking **/
    length_t send_size;
    
    /** Used if status is szkr_status_ready **/
    length_t returned_message_size;
  }          retlen_param;
  szkr_error err_code;
  
  enum szkr_status {
    szkr_status_handshaking,
    szkr_status_ready,
    szkr_status_error
  } status;
} szkr_resp_t;

/** Sazukari API declarations **/
length_t    szkr_get_ctx_size();
int         szkr_bootstrap();
int         szkr_new_ctx(szkr_ctx_t* ctx);
szkr_resp_t szkr_start_connection(szkr_ctx_t*, byte* out_buffer, length_t buflen);
szkr_resp_t szkr_incoming(szkr_ctx_t* ctx, byte* buffer, length_t len);
szkr_resp_t szkr_compile_message(szkr_ctx_t* ctx, const byte* msg, length_t msglen,
                                 byte* out_buffer, length_t buflen);
length_t    szkr_deduce_expected_length(szkr_ctx_t* ctx, const byte* hdr); 
int         szkr_reset_state(szkr_ctx_t* ctx);
int         skzr_destroy();
/** End Sazukari API declarations **/

/** End Sazukari public declarations **/
#endif // __SAZUKARI_H__