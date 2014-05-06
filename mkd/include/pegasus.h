#ifndef __PEGASUS_H__
#define __PEGASUS_H__
#include "common.h"
#include <sys/time.h>
#include <stdio.h>

/* Is this a debug build? */
#ifdef DEBUG
#define PEGASUS_DEBUG
#endif

/** Typedefs for MKD Pegasus **/
typedef int (*pegasus_start_broker_cb)(void* param);
/** End typedefs for MKD Pegasus **/

typedef struct pegasus_conf_t {
  /*** Configuration options for MKD Pegasus ***/

  /*** Callback to start a message broker in the current process ***/
  pegasus_start_broker_cb start_broker_cb;

  /*** Parameter to start_broker_cb ***/
  void*                   start_broker_cb_param;

  /*** Length of the context data structure to relay to the broker ***/
  length_t                context_data_length;

  /*** Number of preforked minion processes to keep around ***/
  int                     minion_pool_size;

  /*** How detailed should Pegasus be when logging? ***/
  loglevel                log_level;   
  
  /*** File pointer to log to, if log_level < LOG_QUIET ***/
  FILE*                   log_file;

  /*** Maximum seconds to wait on semaphore locks ***/
  int                     lock_timeout;

  /*** Maximum time to wait on minion responses ***/
  struct timeval          message_timeout;

  /*** Free space to add at the end of each allocated buffer ***/
  length_t                buffer_sentinel;
  /** End configuration options for MKD Pegasus **/
} pegasus_conf_t;

/** Prototype for MKD Pegasus context **/
typedef struct pegasus_ctx_t pegasus_ctx_t;

/** Public functions for MKD Pegasus **/
void        pegasus_version(int* major, int* minor, int* revision, char** suffix);
const char* pegasus_strversion();
int         pegasus_getcontextsize();
int         pegasus_init(pegasus_conf_t* config);
int         pegasus_new_ctx(pegasus_ctx_t* ctx, byte* ctxdata);
int         pegasus_handle_message(pegasus_ctx_t* ctx, const byte* buf, 
              length_t msglen, byte** response, length_t* resplen);
void        pegasus_destroy_ctx(pegasus_ctx_t* ctx);
void        pegasus_cleanup();
/** End public functions for MKD Pegasus **/

#endif // __PEGASUS_H__
