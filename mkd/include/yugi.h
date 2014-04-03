#ifndef __YUGI_H__
#define __YUGI_H__
#include <stdio.h>
#include "yami.h"
#include "common.h"

/** Is this a debug build? **/
#ifdef DEBUG
#define YUGI_DEBUG
#endif

typedef struct yugi_conf_t {
  /** Configuration options for MKD Yugi **/
  
  /*** On what address to listen ***/
  char*          listen_address;
  
  /*** On what port to listen ***/
  int            listen_port;
  
  /*** Daemonize (run in background or not ***/
  int            daemonize;
  
  /*** How much threads to spawn? Suggested is min(num_cores - 1, 1) ***/
  int            thread_count;
  
  /*** Global wait queue size, high value suggested ***/
  int            queue_size;
  
  /*** How much should Yugi wait for a reply before it considers it
   *** timed out? (in ms) ***/ 
  int            receive_timeout;
  
  /*** Maximum buffer length. This primarily affects Yugi's inner
   *** workings with libuv, it typically shouldn't be less than 1024.
   ***/   
  int            buffer_length;
  
  /*** How detailed should Yugi be when logging? ***/
  loglevel       log_level;
  
  /*** File pointer to log to, if log_level < LOG_QUIET ***/
  FILE*          log_file;
  
  /*** How long should the socket backlog be? Refer to listen(2) for
   *** details on this argument ***/
   int           socket_backlog;
   
   /*** How often (in ms) should the watchdog timer tick ***/
   int           watchdog_interval;
  /** End configuration options for MKD Yugi **/
} yugi_conf_t;

/** Prototype for MKD Yugi context */
typedef struct yugi_t yugi_t;

void        yugi_version(int* major, int* minor, int* revision, char** suffix);
const char* yugi_strversion();
int         yugi_getcontextsize();
int         yugi_init(yugi_t* context, yugi_conf_t* config);
int         yugi_start(yugi_t* context);
void        yugi_stop(yugi_t* context);
void        yugi_cleanup(yugi_t* context);

#endif // __YUGI_H__
