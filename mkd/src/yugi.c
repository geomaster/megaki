#include "yugi.h"
#include "common.h"
#include "threadpool.h"
#include <uv.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <semaphore.h>

#define YUGI_VERSION_MAJOR              0
#define YUGI_VERSION_MINOR              1
#define YUGI_VERSION_REVISION           0
#define YUGI_VERSION_SUFFIX             "-privt"

#define YUGI_MESSAGE_HARD_LIMIT         131072
#define YUGI_BUFFER_SIZE                4096
#define YUGI_DEBUG
/** Log macros **/
#define YUGI_LOGF(lvl, fmt, ...) \
  if (yc->config.log_level <= (lvl)) { \
    MEGAKI_LOGF(yc->config.log_file, "YUGI", fmt, __VA_ARGS__); \
  }
  
#define YUGI_LOGS(lvl, str) \
  if (yc->config.log_level <= (lvl)) { \
    MEGAKI_LOGS(yc->config.log_file, "YUGI", str); \
  }
/** End log macros **/

/** Debug macros **/
#include <assert.h>
#define YUGI_ASSERT(cond, msg) \
  assert((cond) && msg)

#ifdef YUGI_DEBUG
#define YUGI_LOGCONNF(c, fmt, ...) \
  YUGI_LOGF(LOG_DEBUG2, "[%s] " fmt, (c)->dbg_id, __VA_ARGS__)

#define YUGI_LOGCONNS(c, str) \
  YUGI_LOGF(LOG_DEBUG2, "[%s] " str, (c)->dbg_id)
#else
#define YUGI_LOGCONNF(c, fmt, ...)
#define YUGI_LOGCONNS(c, str)
#endif

  
/** End debug macros **/

/** Internal macros **/
#define YUGI_CYAMI(conn) \
  ((yami_ctx_t*)((byte*)(conn) + sizeof(conn_t)))
  
#define YUGI_ASYNC_END_BOILERPLATE(handle) \
  uv_close((uv_handle_t*) (handle), &on_close_async)
  
#define YUGI_GRAB_ASYNC_END_BOILERPLATE(handle, c) \
  release_connection((c)); \
  uv_close((uv_handle_t*) (handle), &on_close_async)

#define YUGI_NONFAIL(f) \
  if (!(f)) { \
    YUGI_LOGF(LOG_FATAL, \
        "A non-fail call (%s) has failed: unsafe to continue", \
        #f \
    ); \
    YUGI_ASSERT(0, "Non-fail call failure"); \
  }

/** End internal macros **/

/** Globals **/
char yugi__version[ 100 ];
/** End globals **/


/** Internal structs */
typedef struct conn_node_t conn_node_t;

typedef struct yugi_t {
  threadpool_t      *pool;
  uv_loop_t         *uv_loop;
  uv_tcp_t          uv_servconn;
  uv_timer_t        uv_watchdog;
  byte              *uv_buffer;
  yugi_conf_t       config;
  int               killswitch,
                    dropped_connections,
                    connection_count;
  conn_node_t       *connections;
  
  /** Queried from Yami **/
  length_t          yami_iniths_len;
  length_t          yami_context_len;
} yugi_t;

typedef struct conn_t {
  uv_stream_t         *stream;
  byte                recvbuf[ YUGI_BUFFER_SIZE ],
                      *dynrecvbuf,
                      is_closed,
                      is_timed;
  pthread_mutex_t     refmut;
  struct sockaddr_in  addr;
  sem_t               recvmut;
  int                 recvlen,
                      sndlen,
                      refcount,
                      tunnelheadlen,
                      expectlen,
                      dynrecvbufsz,
                      schedexpectlen;
  yugi_t              *parent;
  conn_node_t         *node;
  yami_resp_t         yami_resp;
  uv_timer_t          timeout_tmr;
  
#ifdef YUGI_DEBUG
  char              dbg_id[ 10 ];
#endif
} conn_t;


typedef struct conn_node_t {
  conn_t            *cptr;
  
  struct
  conn_node_t       *prev,
                    *next;
} conn_node_t;
/** End internal structs **/

/** Prototypes for internal procedures **/
void grab_connection(conn_t* c);
void release_connection(conn_t* c);
void job_handle_message(void* data);
void walk_and_destroy(uv_handle_t* handle, void* arg);
int  close_connection(conn_t* c);
void close_connection_async(conn_t* c);
void kill_timeout_timer(conn_t* c);
int  spawn_async(yugi_t* yc, void* data, uv_async_cb cb);
int  grab_spawn_async(yugi_t* yc, conn_t* c, void* data, uv_async_cb cb);
/** End prototypes for internal procedures **/

/** Prototypes for internal libuv callbacks **/
void on_client_connect(uv_stream_t* server, int status);
void on_premature_close(uv_handle_t* handle);
void on_data_read(uv_stream_t*, ssize_t nread, const uv_buf_t* buf);
void on_data_written(uv_write_t* req, int status);
void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void async_cb_freeconn(uv_async_t* handle);
void async_cb_write_data(uv_async_t* handle);
void async_cb_closeconn(uv_async_t* handle);
void on_close_connection(uv_handle_t* conn);
void on_close_async(uv_handle_t* async);
void on_close_generic_handle(uv_handle_t* handle);
void on_watchdog_tick(uv_timer_t* tmr);
void on_watchdog_close(uv_handle_t* handle);
void on_timeout_tick(uv_timer_t* tmr);
/** End prototypes for internal libuv callbacks **/

#ifdef YUGI_DEBUG
/** Prototypes for debug procedures **/
void dbg_generate_connection_id(char* out_id);
/** End prototypes for debug procedures **/
#endif

/** Public interface for Yugi **/

void yugi_version(int* maj, int* min, int* rev, char** suffix)
{
  *maj = YUGI_VERSION_MAJOR;
  *min = YUGI_VERSION_MINOR;
  *rev = YUGI_VERSION_REVISION;
  *suffix = YUGI_VERSION_SUFFIX;
}

const char* yugi_strversion()
{
  int maj, min, rev;
  char* suff;
  yugi_version(&maj, &min, &rev, &suff);
  snprintf(yugi__version, 99, "%d.%d.%d%s", maj, min, rev, suff);
  return yugi__version;
}

int yugi_getcontextsize() 
{
  return sizeof( yugi_t );
}

int yugi_init(yugi_t* yc, yugi_conf_t* config)
{
  int res;

  /* Config sanity checks */
  if (
      (config->thread_count < 1) ||
      (config->queue_size < 1) ||
      (config->log_level < LOG_QUIET && !config->log_file) ||
      (config->buffer_length <= 0) ||
      (config->receive_timeout <= 0) ||
      (config->socket_backlog <= 0)
     )
    goto failure;
  
  yc->config = *config;
  yc->connections = NULL;
  yc->killswitch = 0;
  yc->pool = threadpool_create(config->thread_count, 
    config->queue_size, 0);
  if (!yc->pool)
    goto failure;

  yc->uv_buffer = (byte*) malloc(config->buffer_length);
  if (!yc->uv_buffer)
    goto failure;
    
  yc->uv_loop = (uv_loop_t*) malloc(sizeof(uv_loop_t));
  if (!yc->uv_loop)
    goto dealloc_buffer;
    
  res = uv_loop_init(yc->uv_loop);
  if (res != 0)
    goto dealloc_loop;
    
  res = uv_timer_init(yc->uv_loop, &yc->uv_watchdog);
  if (res != 0)
    goto delete_loop;
  yc->uv_watchdog.data = yc;
  yc->yami_context_len = yami_getcontextsize();
  
  return(0);
  
delete_loop:
  uv_loop_delete(yc->uv_loop);
  
dealloc_loop:
  free(yc->uv_loop);
  
dealloc_buffer:
  free(yc->uv_buffer);
  
failure:
  return(-1);
}

int yugi_start(yugi_t* yc)
{
  uv_loop_t* l = yc->uv_loop;
  yc->yami_iniths_len = yami_get_tunnel_headlen();
  yc->dropped_connections = 0;
  
  int res = -1;
  YUGI_LOGF(LOG_NOTICE, "Starting Yugi %s", yugi_strversion());
  
  res = uv_timer_start(&yc->uv_watchdog, &on_watchdog_tick,
                       yc->config.watchdog_interval,
                       yc->config.watchdog_interval);
  if (res != 0) {
    YUGI_LOGF(LOG_FATAL, "Could not start watchdog timer (%s)", uv_strerror(res));
    goto failure;
  }
  
  struct sockaddr_in addr;
  res = uv_ip4_addr(yc->config.listen_address, yc->config.listen_port, &addr);
  if (res != 0) {
    YUGI_LOGF(LOG_FATAL, "Could not resolve local hostname %s:%d (%s)",
      yc->config.listen_address, yc->config.listen_port, uv_strerror(res));
    goto failure;
  }
  
  res = uv_tcp_init(l, &yc->uv_servconn);
  yc->uv_servconn.data = (void*) yc;
  if (res != 0) {
    YUGI_LOGF(LOG_FATAL, "Could not initialize TCP handle (%s)", uv_strerror(res));
    goto failure;
  }
  
  res = uv_tcp_bind(&yc->uv_servconn, (struct sockaddr*) &addr, 0);
  if (res != 0) {
    YUGI_LOGF(LOG_FATAL, "Could not bind to %s:%d, is someone else already "
      "bound there? (%s)", yc->config.listen_address, yc->config.listen_port, uv_strerror(res));
    goto failure;
  }
  
  res = uv_listen((uv_stream_t*) &yc->uv_servconn, yc->config.socket_backlog,
    &on_client_connect);
  if (res != 0) {
    YUGI_LOGF(LOG_FATAL, "Could not listen on local address (%s)", uv_strerror(res));
    goto failure;
  }
  
  YUGI_LOGF(LOG_NOTICE, "Yugi %s (libuv %s) listening on %s:%d", yugi_strversion(),
    uv_version_string(), yc->config.listen_address, yc->config.listen_port);
    
  res = uv_run(yc->uv_loop, UV_RUN_DEFAULT);
  if (res != 0) {
    YUGI_LOGS(LOG_FATAL, "Could not start libuv event loop");
    goto failure;
  }

  YUGI_LOGS(LOG_NOTICE, "Main loop stopped");
  
  /* TODO: Cleanup when the loop quits! */
  return(0);
  
failure:
  return(res);
}

void yugi_stop(yugi_t* yc)
{
  if (yc->killswitch) return;

  YUGI_LOGS(LOG_NOTICE, "Stopping Yugi...");
  yc->killswitch = 1;
}

void yugi_cleanup(yugi_t* yc)
{
  int res;  
  YUGI_LOGS(LOG_NOTICE, "Cleaning up Yugi context");
  
  if (yc->pool) {
    YUGI_LOGS(LOG_NOTICE, "Destroying threadpool");
    threadpool_destroy(yc->pool, threadpool_graceful);
    yc->pool = NULL;
  }

  YUGI_LOGS(LOG_NOTICE, "Closing main loop");
  if ((res = uv_loop_close(yc->uv_loop)) != 0) {
    YUGI_LOGF(LOG_WARNING, "Could not close main loop! (%s)", uv_strerror(res));
    return ;
  }
  free(yc->uv_buffer);
  free(yc->uv_loop);
  
    
  YUGI_LOGS(LOG_NOTICE, "Pruning leftover connections...");
  conn_node_t *c, *cn;
  for (c = yc->connections; c; c = cn) {
    yami_destroy_ctx(YUGI_CYAMI(c->cptr));
    cn = c->next;
    if (c->cptr->dynrecvbuf) {
      free(c->cptr->dynrecvbuf);
    }
    free(c->cptr);
    free(c);
  }
  
  YUGI_LOGS(LOG_NOTICE, "Cleanup done, goodbye!");
}

/** End public interface for Yugi **/

/** Private functions for Yugi **/
void close_connection_async(conn_t* c)
{
  grab_spawn_async(c->parent, c, c, async_cb_closeconn);
}

void async_cb_closeconn(uv_async_t* handle)
{
  close_connection((conn_t*) handle->data);
  YUGI_GRAB_ASYNC_END_BOILERPLATE(handle, (conn_t*) handle->data);
}

void kill_timeout_timer(conn_t* c)
{
  uv_timer_stop(&c->timeout_tmr);
  c->is_timed = 0;
  uv_close((uv_handle_t*) &c->timeout_tmr, NULL);
}

void on_client_connect(uv_stream_t* server, int status)
{
  yugi_t* yc = (yugi_t*) server->data;
  int res;
  
  if (status != 0) {
#ifdef YUGI_DEBUG
    YUGI_LOGF(LOG_DEBUG1, "Failed connection attempt (%s)", uv_strerror(status));
#endif
    goto failure;
  }
 
  if (yc->config.max_clients > 0 && 
      yc->connection_count >= yc->config.max_clients) {
    ++yc->dropped_connections;
    goto failure;
  }
  ++yc->connection_count;

  uv_tcp_t* client = malloc(sizeof(uv_tcp_t));
  if ((res = uv_tcp_init(yc->uv_loop, client)) != 0) {
    YUGI_LOGF(LOG_WARNING, "Failed TCP init, not expected behavior (%s)", uv_strerror(res));
    goto dealloc_client;
  }
  
  if ((res = uv_accept(server, (uv_stream_t*) client)) != 0) {
#ifdef YUGI_DEBUG
    YUGI_LOGF(LOG_DEBUG1, "Failed to accept connection (%s)", uv_strerror(res));
#endif
    goto close_client;
  }
  
#ifdef YUGI_DEBUG
  YUGI_LOGS(LOG_DEBUG2, "Connection established!");
#endif
  
  /* we hope libc malloc satisfies these from the fastbin, which
   * really is something that *should* happen */
  /* NB that we allocate memory not only for the connection but also for
   * the yami context! */
  conn_t* conn = (conn_t*) malloc(sizeof( conn_t ) + yc->yami_context_len);
  if (!conn) {
    YUGI_LOGS(LOG_ERROR, "Failed to allocate memory for connection, dropping");
    goto close_client;
  }

  conn->dynrecvbuf = NULL;
  memset(&conn->addr, 0, sizeof(struct sockaddr_in));
  int len = sizeof(struct sockaddr_in);
  uv_tcp_getpeername(client, (struct sockaddr*) &conn->addr, &len);
  
  yami_yugi_payload_t yamip;
  yamip.ip = conn->addr;

  if (yami_new_ctx(YUGI_CYAMI(conn), yamip) != 0) {
    YUGI_LOGS(LOG_ERROR, "Failed to initialize Yami context");
    goto dealloc_connection;
  }

  conn_node_t* cnode = (conn_node_t*) malloc(sizeof( conn_node_t ));
  if (!conn) {
    YUGI_LOGS(LOG_ERROR, "Failed to allocate memory for connection node, dropping");
    goto destroy_yami;
  }
  
  cnode->cptr = conn;
  cnode->next = yc->connections;
  if (yc->connections)
    yc->connections->prev = cnode;
  cnode->prev = NULL;
  yc->connections = cnode;
  
  /*
  pthread_mutex_attr attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
  */
  
  if (sem_init(&conn->recvmut, 0, 1) == -1) {
    YUGI_LOGS(LOG_WARNING, "Failed to init semaphore, dropping");
    goto dealloc_connection_node;
  }

  if (pthread_mutex_init(&conn->refmut, 0) != 0) {
    YUGI_LOGS(LOG_WARNING, "Failed to init mutex, dropping");
    goto destroy_semaphore;
  }

  if ((res = uv_timer_init(yc->uv_loop, &conn->timeout_tmr)) == -1) {
    YUGI_LOGF(LOG_WARNING, "Failed to init timer, dropping (%s)", uv_strerror(res));
    goto destroy_mutexes;
  }
  
  conn->timeout_tmr.data = conn;
  client->data = conn;
  conn->node = cnode;
  conn->parent = yc;
  conn->refcount = 1;
  conn->stream =  (uv_stream_t*) client;
  conn->is_closed = 0;
  conn->is_timed = 1;
  conn->tunnelheadlen = yc->yami_iniths_len;
  conn->recvlen = 0;
  conn->sndlen = 0; 
  conn->expectlen = yc->yami_iniths_len;
  
  /* int len2 = sizeof(struct sokaddr_in); */
  /* uv_tcp_getsockname(client, (struct sockaddr*) &conn->addr, &len2); */

#ifdef YUGI_DEBUG
  dbg_generate_connection_id(conn->dbg_id);
#endif
  
  if ((res = uv_timer_start(&conn->timeout_tmr, &on_timeout_tick, yc->config.receive_timeout,
                            0)) == -1) {
    YUGI_LOGF(LOG_WARNING, "Failed to start timer, dropping (%s)", uv_strerror(res));
    goto dealloc_connection_node;
  }
  
  /* start reading on the client socket */
  if ((res = uv_read_start((uv_stream_t*) client,
                           &alloc_buffer,
                           &on_data_read)) != 0) {
#ifdef YUGI_DEBUG
    YUGI_LOGF(LOG_DEBUG1, "Failed to start reading from connection (%s)",
              uv_strerror(res));
#endif
    goto dealloc_connection_node;
  } else {
    YUGI_LOGCONNS(conn, "Started receiving");
  }
  
  return ;
  
destroy_mutexes:
  pthread_mutex_destroy(&conn->refmut);
 
destroy_semaphore:
  sem_destroy(&conn->recvmut);

dealloc_connection_node:
  yc->connections = cnode->prev;
  free(cnode);
  
destroy_yami:
  yami_destroy_ctx(YUGI_CYAMI(conn));

dealloc_connection:
  free(conn);

close_client:
  uv_close((uv_handle_t*) client, &on_premature_close); /* skip deallocation here because on_premature_close will do it when * the time is right. note the spaghetti */
  goto failure;
        
dealloc_client:
  free(client);
  
failure:
  return ;
}

void on_premature_close(uv_handle_t* handle)
{
  /* just dealloc the handle, needn't do anything else */
  free(handle);
}

void on_data_written(uv_write_t* req, int status)
{
  conn_t* c = (conn_t*) req->data;
  yugi_t* yc = c->parent;
  
  if (status != 0) {
    YUGI_LOGCONNF(c, "Could not write data to stream (%s)", uv_strerror(status));
  }

  YUGI_LOGCONNF(c, "Written %d bytes to stream", c->sndlen);

  c->expectlen = c->schedexpectlen;
  if (!c->yami_resp.end_connection) {
    c->is_timed = 1;
    uv_timer_start(&c->timeout_tmr, &on_timeout_tick, yc->config.receive_timeout, 0);
  } else {
    close_connection(c);
  }

  if (c->yami_resp.uses_new_buffer) {
    free(c->yami_resp.new_buffer);
  }

  release_connection(c);
  free(req);
}

void grab_connection(conn_t* c)
{
  yugi_t *yc = c->parent;
  YUGI_ASSERT(c->refcount >= 1, "This connection has already been destroyed "
                                "which indicates a bug");

  YUGI_NONFAIL(pthread_mutex_lock(&c->refmut) == 0);
  c->refcount++;
  YUGI_NONFAIL(pthread_mutex_unlock(&c->refmut) == 0);
}

void release_connection(conn_t* c)
{
  yugi_t* yc = c->parent;
  
  YUGI_ASSERT(c->refcount >= 1, "This connection has already been destroyed "
                                "which indicates a bug");
  
  YUGI_NONFAIL(pthread_mutex_lock(&c->refmut) == 0);
  int newrc = --c->refcount;
  YUGI_NONFAIL(pthread_mutex_unlock(&c->refmut) == 0);
  
  if (newrc <= 0) {
    YUGI_LOGCONNS(c, "Spawning async to free connection");
    spawn_async(c->parent, c, &async_cb_freeconn);
  }
}

void async_cb_freeconn(uv_async_t* handle)
{
  conn_t* c = (conn_t*) handle->data;
  yugi_t* yc = c->parent;
  
  YUGI_ASSERT(c->refcount == 0,
    "Freeing a connection with non-zero refcount, this indicates a bug");
             
  YUGI_LOGCONNS(c, "FreeAsync: freeing now");
  conn_node_t* cnode = c->node;
  if (cnode->prev)
    cnode->prev->next = cnode->next;
  else yc->connections = cnode->next;
  
  if (cnode->next)
    cnode->next->prev = cnode->prev;
  
  sem_destroy(&c->recvmut);  
  pthread_mutex_destroy(&c->refmut);
  if (c->dynrecvbuf)
    free(c->dynrecvbuf);
  free(cnode);
  free(c);
  YUGI_ASYNC_END_BOILERPLATE(handle);
}

void async_cb_write_data(uv_async_t* handle)
{
  conn_t* c = (conn_t*) handle->data;
  
  uv_write_t* req = (uv_write_t*) malloc(sizeof(uv_write_t));
  
  byte* buf;
  if (c->yami_resp.uses_new_buffer) 
    buf = c->yami_resp.new_buffer;
  else 
    buf = c->recvbuf;

  uv_buf_t bufdef = { .base = (char*)buf, .len = c->sndlen };
  req->data = c;
  
  if (uv_write(req, c->stream, &bufdef, 1, on_data_written) != 0) {
#ifdef YUG_DEBUG
    YUGI_LOGCONNS(c, "Writing failed");
#endif
    if (c->yami_resp.uses_new_buffer)
      free(c->yami_resp.new_buffer);
    
    release_connection(c);
    free(req); 
  }

  YUGI_ASYNC_END_BOILERPLATE(handle);
}

int spawn_async(yugi_t* yc, void* data, uv_async_cb cb)
{
  uv_async_t* async = (uv_async_t*) malloc(sizeof( uv_async_t ));
  int res;
  if (!async) {
    YUGI_LOGS(LOG_ERROR, "Failed to allocate memory for async");
    res = -1;
    goto failure;
  }
  
  async->data = data;
  if ((res = uv_async_init(yc->uv_loop, async, cb)) == -1) {
    YUGI_LOGF(LOG_ERROR, "Failed to init async (%s)", uv_strerror(res));
    goto dealloc_async;
  }
  
  if ((res == uv_async_send(async)) == -1) {
    YUGI_LOGF(LOG_ERROR, "Failed to send async (%s)", uv_strerror(res));
    goto dealloc_async;
  }
  
  return( 0 );
  
dealloc_async:
  free(async);
  
failure:
  return( res );
}

int grab_spawn_async(yugi_t* yc, conn_t* c, void* data, uv_async_cb cb)
{
  grab_connection(c);
  
  uv_async_t* async = (uv_async_t*) malloc(sizeof( uv_async_t ));
  int res;
  
  if (!async) {
    YUGI_LOGS(LOG_ERROR, "Failed to allocate memory for async");
    res = -1;
    goto release_conn;
  }
  
  async->data = data;
  if ((res = uv_async_init(yc->uv_loop, async, cb)) == -1) {
    YUGI_LOGF(LOG_ERROR, "Failed to init async (%s)", uv_strerror(res));
    goto dealloc_async;
  }
  
  if ((res == uv_async_send(async)) == -1) {
    YUGI_LOGF(LOG_ERROR, "Failed to send async (%s)", uv_strerror(res));
    goto dealloc_async;
  }
  
  return( 0 );
  
dealloc_async:
  free(async);
  
release_conn:
  release_connection(c);
  return( res );
}

void on_data_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
  conn_t* c = (conn_t*) stream->data;
  yugi_t* yc = c->parent;
  if (nread < 0) {
    YUGI_LOGCONNF(c, "Connection reported dead, destroying (%s)", uv_strerror(nread));
    goto close_conn;
  }
  
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
    goto close_conn;
  ts.tv_sec += yc->config.lock_timeout;

  YUGI_LOGCONNF(c, "Incoming %d bytes", (int) nread);

  if (sem_timedwait(&c->recvmut, &ts) != 0) {
    YUGI_LOGCONNS(c, "Killing connection, could not lock semaphore");
    YUGI_LOGS(LOG_WARNING, "Semaphore wait failed (probably timeout), dropping connection");
    goto close_conn;
  }

  int newsize = c->recvlen + (int) nread;
  uv_timer_start(&c->timeout_tmr, &on_timeout_tick, yc->config.receive_timeout, 0);
  
  byte* dynrecvbuf = NULL;
  if (!c->dynrecvbuf &&
      newsize >= c->tunnelheadlen) {
    YUGI_LOGCONNS(c, "Asking Yami for expected length");
    int res = yami_get_packetlen(YUGI_CYAMI(c), (byte*) buf->base, (length_t*) &c->expectlen);
    
    if (!res) {
      YUGI_LOGCONNS(c, "Yami does not approve of the tunnel header, closing connection");
      goto close_conn;
    } else {
      YUGI_LOGCONNF(c, "Yami expects %d bytes of additional data",
                          c->expectlen - c->tunnelheadlen);
      if (c->expectlen > yc->config.buffer_length) {
        dynrecvbuf = malloc(yc->config.buffer_length);
        if (!dynrecvbuf) {
          YUGI_LOGS(LOG_ERROR, "Couldn't allocate memory for dynrecvbuffer, dropping "
              "connection");
          goto close_conn;
        }

        c->dynrecvbuf = dynrecvbuf;
        c->dynrecvbufsz = yc->config.buffer_length;
      }
    }
  }

  if (newsize > c->expectlen) {
    YUGI_LOGCONNF(c, "expect:%d newsize:%d nread:%d\n", (int)c->expectlen, (int)newsize, (int)nread);
    YUGI_LOGCONNS(c, "Bombed by too much data; killing connection");
    goto dealloc_dynrecvbuf;
  }
  
  if (c->expectlen > yc->config.buffer_length) {
    if (newsize >= c->dynrecvbufsz) {
      c->dynrecvbuf = realloc(c->dynrecvbuf, c->dynrecvbufsz + yc->config.buffer_length);
      if (!c->dynrecvbuf) {
        YUGI_LOGS(LOG_ERROR, "Could not reallocate block to bigger size, killing "
            "connection");
        goto dealloc_dynrecvbuf;
      }
      c->dynrecvbufsz += yc->config.buffer_length;
    }
    memcpy(c->dynrecvbuf + c->recvlen, buf->base, nread);
  } else {
    memcpy(c->recvbuf + c->recvlen, buf->base, nread);
  }
  c->recvlen = newsize;

  if (newsize == c->expectlen) {
    YUGI_LOGCONNF(c, "Calling Yami to handle message of %d bytes", newsize);
    
    /* grab the connection for the thread, stop the timer and set expectlen
     * to -1: this will make yugi terminate the connection if new, unexpected
     * data is received.
     * 
     * since megaki is based on a request-response model with a (low) fixed maximum
     * message length, there is no point in piling this data up, because 
     * while one thread processes the request, no response has been sent,
     * so any new data received is erroneous. */
    uv_timer_stop(&c->timeout_tmr);
    c->is_timed = 0;
    c->expectlen = -1;
    grab_connection(c);
    if (threadpool_add(yc->pool, &job_handle_message, c, 0) != 0) {
      release_connection(c);
      ++yc->dropped_connections;
      goto unlock_mut;
    }
  }

  YUGI_NONFAIL(sem_post(&c->recvmut) == 0);
  return ;
  
unlock_mut:
  YUGI_NONFAIL(sem_post(&c->recvmut) == 0);

dealloc_dynrecvbuf:
  if (c->dynrecvbuf) {
    free(c->dynrecvbuf);
    c->dynrecvbuf = NULL;
  }
close_conn:
  if (close_connection(c) != 0) {
    YUGI_LOGCONNS(c, "Could not close connection");
  }
    
  return ;
}

void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
  conn_t* c = (conn_t*) handle->data;
  yugi_t* yc = c->parent;
  
  *buf = uv_buf_init((char*) yc->uv_buffer, yc->config.buffer_length);
}

void job_handle_message(void* data)
{
  conn_t* c = (conn_t*) data;
  yugi_t* yc = c->parent;
  
  length_t len = c->recvlen;
  c->recvlen = 0;
  YUGI_NONFAIL(sem_post(&c->recvmut) == 0);

  byte *buf = c->recvbuf;
  int uses_dynrecvbuf = 0;
  if (c->dynrecvbuf) {
    buf = c->dynrecvbuf;
    uses_dynrecvbuf = 1;
  }

  yami_resp_t resp = yami_incoming(YUGI_CYAMI(c), buf, len);
  c->yami_resp = resp;
  if (uses_dynrecvbuf) {
    free(buf);
    c->dynrecvbuf = NULL;
  }
  c->sndlen = resp.data_size;
  
  if (!c->is_closed && resp.data_size > 0) {
    YUGI_LOGCONNF(c, "Sending %d bytes of data from Yami", resp.data_size);
    grab_spawn_async(yc, c, c, async_cb_write_data);
  } else if (resp.end_connection) {
    if (!c->is_closed) {
      YUGI_LOGCONNS(c, "Closing connection as requested by Yami");

      close_connection_async(c);
    }
  } else {
    if (resp.tunneling_header_length > 0) {
      c->schedexpectlen = resp.tunneling_header_length;
      c->tunnelheadlen = resp.tunneling_header_length;
    }
  }

/* dealloc_yamibuf: */
  /* if (resp.uses_new_buffer) */
  /*   free(resp.new_buffer); */

/* quit: */
  release_connection(c);
}

int close_connection(conn_t* c)
{
  int res = 0;
  yugi_t* yc = c->parent;
 
  YUGI_LOGCONNS(c, "Closing connection");
  yami_destroy_ctx(YUGI_CYAMI(c));
  kill_timeout_timer(c);

  --yc->connection_count;
  if (c->is_closed)
    return(0); /* already done */
  else {
    c->is_closed = 1;
    if (!uv_is_closing(c->stream))
      uv_close((uv_handle_t*) c->stream, &on_close_connection);
  } 
  return(res);
}

void on_close_connection(uv_handle_t* h)
{
  conn_t* c = (conn_t*) h->data;
  c->is_closed = 1;
  free(h);
  release_connection(c);
}

void on_close_generic_handle(uv_handle_t* handle)
{
  free(handle);  
}

void on_close_async(uv_handle_t* async)
{
  free(async);
}

void walk_and_destroy(uv_handle_t* handle, void* arg)
{
  yugi_t* yc = (yugi_t*) arg;
  
  if (handle == (uv_handle_t*) &yc->uv_watchdog)
    return ;
    
  static int x = 0;
#ifdef YUGI_DEBUG
  YUGI_LOGF(LOG_DEBUG2, "Destroying handle %p (%d)", handle, ++x);
#endif
  
  if (handle != (uv_handle_t*) &yc->uv_servconn &&
      !(handle->type == UV_TIMER && (uv_timer_t*) handle == &((conn_t*)handle->data)->timeout_tmr) &&
      !uv_is_closing(handle)) {    
    uv_close(handle, &on_close_generic_handle);
  } else {
    uv_close(handle, NULL);
  }
}

void on_watchdog_tick(uv_timer_t* tmr)
{
  yugi_t* yc = (yugi_t*) tmr->data;
  if (yc->killswitch) {
    yc->killswitch = 0;

    if (yc->pool) {
      YUGI_LOGS(LOG_NOTICE, "Destroying threadpool");
      threadpool_destroy(yc->pool, threadpool_graceful);
      yc->pool = NULL;
    }

    YUGI_LOGS(LOG_NOTICE, "WATCHDOG: Destroying handles...");
    uv_walk(yc->uv_loop, &walk_and_destroy, yc);
    YUGI_LOGS(LOG_NOTICE, "WATCHDOG: Handles destroyed");  
    YUGI_LOGS(LOG_NOTICE, "WATCHDOG: Destroying self");
    uv_close((uv_handle_t*) tmr, &on_watchdog_close);
  } else if (yc->dropped_connections > 0) {
    YUGI_LOGF(LOG_WARNING, "WATCHDOG: Server overloaded, dropped %d "
              "connections as a result!!!", yc->dropped_connections);
    yc->dropped_connections = 0;
  }
}

void on_watchdog_close(uv_handle_t* tmr)
{
  yugi_t* yc = (yugi_t*) tmr->data;  
  YUGI_LOGS(LOG_NOTICE, "WATCHDOG: Stopping loop");
  uv_stop(yc->uv_loop);
}

void on_timeout_tick(uv_timer_t* tmr)
{
  conn_t* c = (conn_t*) tmr->data;
#ifdef YUGI_DEBUG
  yugi_t* yc = c->parent;
#endif
  
  YUGI_LOGCONNS(c, "Timeout timer tick");
  if (!c->is_closed && c->is_timed) {
#ifdef YUGI_DEBUG
    YUGI_LOGCONNS(c, "Connection timed out, closing");
#endif

    close_connection(c);
  }
  else if (!c->is_timed)
    uv_close((uv_handle_t*) tmr, NULL);
}
#ifdef YUGI_DEBUG
void dbg_generate_connection_id(char* out_id)
{
  static const char consonants[] = 
    "BCDFGHJKLMNPQRSTVWXZ",
                    vowels[] =
    "AEIOU";
    
  int i;
  for (i = 0; i < 9; ++i)
    out_id[i] = (i % 2 == 0 ?
      consonants[rand() % (sizeof(consonants) - 1)] :
      vowels[rand() % (sizeof(vowels) - 1)]
    );
  out_id[9] = '\0';
  
}
#endif 
/** End private functions for MKD Yugi **/
