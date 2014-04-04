#ifndef __YAMI_H__
#define __YAMI_H__
#include "common.h"
#define YAMI_MAX_PACKET_LENGTH            8400
#define YAMI_MAX_PACKET_VARIANCE          2

/** Is this a debug build? **/
#ifdef DEBUG
#define YAMI_DEBUG
#endif

typedef struct yami_conf_t {
  /** Configuration options for MKD Yami **/
  
  /*** Server certificate raw data and size ***/
  byte*         certificate_buffer;
  length_t      certificate_size;
  
  /*** If not NULL, zero-terminated string containing the passphrase
   *** for the certificate data ***/
  const char*   certificate_passphrase;
  
  /*** File to load random data from, or NULL ***/
  const char*   random_file;
  
  /*** Bytes of randomness to load from the random_file **/
  length_t      random_bytes;
  
} yami_conf_t;

/** Yami structures **/
typedef struct yami_ctx_t yami_ctx_t;

typedef struct yami_resp_t {
  byte      end_connection;
  length_t  data_size,
            tunneling_header_length;
} yami_resp_t;
/** End Yami structures **/

/** Yami public interface **/
void        yami_version(int* major, int* minor, int* revision, char** suffix);
const char* yami_strversion();
int         yami_getcontextsize();
int         yami_init(yami_conf_t* config);
length_t    yami_get_tunnel_headlen();
int         yami_get_packetlen(yami_ctx_t* ctx, byte* header,
                               length_t* o_len);
void        yami_new_ctx(yami_ctx_t* ctx);
yami_resp_t yami_incoming(yami_ctx_t* ctx, byte* buffer, length_t length);
//void        yami_destroy_ctx(yami_ctx_t* ctx);
void        yami_destroy();
/** End Yami public interface **/

#endif // __YAMI_H__
