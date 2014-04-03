#ifndef __MEGAKI_SERVER_H__
#define __MEGAKI_SERVER_H__
#include <stdint.h>

struct mgk_serverctx;
struct mgk_serverauth;

typedef struct mgk_serverctx mgk_serverctx;

typedef uint8_t byte;
typedef uint32_t length_t;

int mgk_rand_seed(const byte* buf, length_t count);

int mgk_init_server_ctx(mgk_serverctx** ctx, FILE* auth_source, const char* auth_passphrase);
int mgk_decode_syn(mgk_serverctx* ctx, byte* buf, length_t* buf_len);
int mgk_build_synack(mgk_serverctx* ctx, const byte* buf, length_t buf_len);
int mgk_decode_ack(mgk_serverctx* ctx, byte* buf, length_t* buf_len);

int mgk_encrypt_message(mgk_serverctx* ctx, byte* ibuf, length_t ibuf_len,
  byte* obuf, length_t *obuf_len);
int mgk_decrypt_message(mgk_serverctx* ctx, const byte* ibuf, length_t ibuf_len,
  byte* obuf, length_t *obuf_len);
  
void mgk_destroy_server_ctx(mgk_serverctx** ctx);

#endif
