#ifndef __MEGAKI_COMMON_H__
#define __MEGAKI_COMMON_H__
#include <stdint.h>
#ifdef DEBUG
#include <time.h>
#endif

/** Common defs for Megaki protocol **/
#define MEGAKI_RSA_KEYSIZE                2048
#define MEGAKI_RSA_EXPSIZE                32
#define MEGAKI_MAGIC_BYTES                5
#define MEGAKI_PACKET_TYPE_BYTES          1
#define MEGAKI_AES_KEYSIZE                256
#define MEGAKI_AES_BLOCK_BYTES            16
#define MEGAKI_TOKEN_BYTES                16
#define MEGAKI_ERROR_CODE_BYTES           MEGAKI_AES_KEYBYTES
#define MEGAKI_HASH_BYTES                 32
#define MEGAKI_VERSION_BYTES              2
#define MEGAKI_LENGTH_BYTES               4

#define MEGAKI_AES_KEYBYTES               (MEGAKI_AES_KEYSIZE / 8)
#define MEGAKI_RSA_EXPBYTES               (MEGAKI_RSA_EXPSIZE / 8)
#define MEGAKI_RSA_KEYBYTES               (MEGAKI_RSA_KEYSIZE / 8)

typedef uint8_t byte;
typedef uint32_t length_t;
typedef int32_t slength_t;

typedef enum loglevel {
  LOG_DEBUG2,
  LOG_DEBUG1,
  LOG_NOTICE,
  LOG_WARNING,
  LOG_ERROR,
  LOG_FATAL,
  LOG_QUIET
} loglevel;

#define MEGAKI_TIMEFMT "%d/%b/%Y:%H:%M:%S %z"
#define MEGAKI_TIMEBUF  30
#define MEGAKI_FMTIME(s) \
  {   \
    struct tm ts; \
    time_t times = time(NULL); \
    localtime_r(&times, &ts); \
    strftime((s), sizeof((s)), MEGAKI_TIMEFMT, &ts); \
  }
  
#define MEGAKI_LOGS(file, comp, str) \
  { \
    char s[MEGAKI_TIMEBUF]; \
    MEGAKI_FMTIME(s); \
    fprintf((file), "[" comp " %s] %s\n", s, str); \
  } 
  
#define MEGAKI_LOGF(file, comp, fmt, ...) \
  { \
    char s[MEGAKI_TIMEBUF]; \
    MEGAKI_FMTIME(s); \
    fprintf((file), "[" comp " %s] " fmt "\n", s, __VA_ARGS__); \
  } 

#endif
