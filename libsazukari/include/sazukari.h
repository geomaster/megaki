#ifndef __SAZUKARI_H__
#define __SAZUKARI_H__
#include "common.h"

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
  length_t   new_expected_size,
             send_size;
  szkr_error err_code;
  
  enum szkr_status {
    szkr_status_handshaking,
    szkr_status_ready,
    szkr_status_error
  } status;
};

length_t    szkr_get_ctx_size();
length_t    szkr_get_min_buffer_size();
int         szkr_init(szkr_ctx_t* ctx);
szkr_resp_t szkr_incoming(szkr_ctx_t* ctx, byte* buffer, length_t len);
szkr_resp_t szkr_send_message(szkr_ctx_t* ctx, const byte* msg, length_t msglen,
                              byte* out_buffer, length_t buflen);

#endif // __SAZUKARI_H__