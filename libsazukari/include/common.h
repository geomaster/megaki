#ifndef __MEGAKI_COMMON_H__
#define __MEGAKI_COMMON_H__
#include <stdint.h>

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

#endif
