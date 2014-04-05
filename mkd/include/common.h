#ifndef __MEGAKI_COMMON_H__
#define __MEGAKI_COMMON_H__
#include <stdint.h>
#ifdef DEBUG
#include <time.h>
#endif

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
#ifdef DEBUG
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
#else
#define MEGAKI_FMTIME(s)
#define MEGAKI_LOGS(file, comp, str)
#define MEGAKI_LOGF(file, comp, fmt, ...)
#endif

#endif
