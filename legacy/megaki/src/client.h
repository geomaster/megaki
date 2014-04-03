#ifndef __MEGAKI_CLIENT_H__
#define __MEGAKI_CLIENT_H__
#include <stdint.h>

struct mgk_clientctx;
struct mgk_serverauth;

typedef struct mgk_clientctx mgk_clientctx;
typedef struct mgk_serverauth mgk_serverauth;

typedef uint8_t byte;
typedef uint32_t length_t;

int mgk_rand_seed(const byte* buf, length_t count);

int mgk_init_client_ctx(mgk_clientctx** ctx, const mgk_serverauth* auth_data);
int mgk_build_syn(mgk_clientctx* ctx, byte* buf, length_t* buf_len);
int mgk_decode_synack(mgk_clientctx* ctx, const byte* buf, length_t buf_len);
int mgk_check_synack_error(mgk_clientctx* ctx, byte *error_code);
int mgk_build_ack(mgk_clientctx* ctx, byte* buf, length_t* buf_len);
int mgk_build_restart(mgk_clientctx* ctx, byte* buf, length_t* buf_len);

length_t mgk_get_encrypted_size(length_t cleartext_size);
int mgk_encrypt_message(mgk_clientctx* ctx, byte* ibuf, length_t ibuf_len,
  byte* obuf, length_t *obuf_len);
int mgk_decrypt_message(mgk_clientctx* ctx, const byte* ibuf, length_t ibuf_len,
  byte* obuf, length_t *obuf_len);
  
void mgk_destroy_client_ctx(mgk_clientctx** ctx);

#endif 
