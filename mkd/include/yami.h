#ifndef __YAMI_H__
#define __YAMI_H__
#include "common.h"
/* for sockaddr_in */
#include <arpa/inet.h>
#define YAMI_MAX_PACKET_LENGTH            MEGAKI_MAX_PACKETSIZE

/** Is this a debug build? **/
#ifdef DEBUG
#define YAMI_DEBUG
#endif

#define pk __attribute__((__packed__))

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
  int       end_connection,
            uses_new_buffer;
  byte*     new_buffer;
  length_t  data_size,
            tunneling_header_length;
} yami_resp_t;

typedef struct pk yami_yugi_payload_t {
  struct sockaddr_in ip;
} yami_yugi_payload_t;

/* Keep this in sync with pmdk.h, or protocol incompatiblity
 * will render your pegasus-minion interface unusable */
typedef struct pk yami_pegasus_payload_t {
  yami_yugi_payload_t yugi_pl;
  byte                token[ MEGAKI_TOKEN_BYTES ];
} yami_pegasus_payload_t;

/** End Yami structures **/

/** Yami public interface **/
void        yami_version(int* major, int* minor, int* revision, char** suffix);
const char* yami_strversion();
int         yami_getcontextsize();
int         yami_init(yami_conf_t* config);
length_t    yami_get_tunnel_headlen();
int         yami_get_packetlen(yami_ctx_t* ctx, byte* header,
                               length_t* o_len);
int         yami_new_ctx(yami_ctx_t* ctx, yami_yugi_payload_t payload);
void        yami_destroy_ctx(yami_ctx_t* ctx);
/** Make sure that there is space for at least YAMI_MAX_PACKET_LENGTH in buffer **/
yami_resp_t yami_incoming(yami_ctx_t* ctx, byte* buffer, length_t length);
void        yami_destroy();
/** End Yami public interface **/

#endif // __YAMI_H__
