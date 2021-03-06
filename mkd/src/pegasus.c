#include "pegasus.h"
#include <pthread.h>
#include <malloc.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <inttypes.h>
#include "pmdk.h"

#define PEGASUS_VERSION_MAJOR              0
#define PEGASUS_VERSION_MINOR              1
#define PEGASUS_VERSION_REVISION           0
#define PEGASUS_VERSION_SUFFIX             "-privt"

/** Log macros **/
#define PEGASUS_LOGF(lvl, fmt, ...) \
  if (pegasus__config.log_level <= (lvl)) { \
    MEGAKI_LOGF(pegasus__config.log_file, "PGSS", fmt, __VA_ARGS__); \
  }
  
#define PEGASUS_LOGS(lvl, str) \
  if (pegasus__config.log_level <= (lvl)) { \
    MEGAKI_LOGS(pegasus__config.log_file, "PGSS", str); \
  }
/** End log macros **/

/** Debug macros **/
#include <assert.h>
#define PEGASUS_ASSERT(cond, msg) \
  assert((cond) && msg)
/** End debug macros **/

#define PEGASUS_NONFAIL(f) \
  if (!(f)) { \
    PEGASUS_LOGF(LOG_FATAL, \
        "A non-fail call (%s) has failed: unsafe to continue", \
        #f \
    ) \
    PEGASUS_ASSERT(0, "Non-fail call failed"); \
  }

/** Internal structures for MKD Pegasus **/
typedef struct pegasus_minion_t {
  int             fds[2];
  pid_t           pid;
  int             is_unstable;
} pegasus_minion_t;

typedef struct pegasus_ctx_t {
  pegasus_minion_t* minion;
  pegasus_guid_t  guid;
} pegasus_ctx_t;

/** End internal structures for MKD Pegasus **/

/** Global variables **/
pegasus_conf_t     pegasus__config;
char               pegasus__version[100];
pegasus_minion_t*  pegasus__minions; 
pegasus_minion_t** pegasus__mq; /* minion free queue */
pthread_mutex_t    pegasus__mqmut; /* minion free queue mutex */
pthread_mutex_t    pegasus__guidmut; /* guid mutex */
sem_t              pegasus__mqsem; /* mq semaphore */
int                pegasus__mqsz; /* mq size */
uint64_t           pegasus__guid;
/** End global variables **/

/** Start internal functions **/
int prefork_minions(int count);
int minion_init(pegasus_minion_t* min, byte* mindata, pegasus_guid_t* opguid);
int broker_surrogate(pid_t mypid, int me2master[2], int master2me[2]);
void minion_destroy(pegasus_minion_t* min, pegasus_guid_t guid);
int read_packet(int fd, byte* buffer, length_t packetlen);
int write_packet(int fd, const byte* buffer, length_t packetlen);
int prefork_minion(pegasus_minion_t* min);
void smite_minion(pegasus_minion_t* min);
/** End internal functions **/

/** Pegasus public interface **/
void pegasus_version(int* major, int* minor, int* revision, char** suffix)
{
  *major = PEGASUS_VERSION_MAJOR;
  *minor = PEGASUS_VERSION_MINOR;
  *revision = PEGASUS_VERSION_REVISION;
  *suffix = PEGASUS_VERSION_SUFFIX;
}

const char* pegasus_strversion()
{
  int maj, min, rev;
  char* suff;
  pegasus_version(&maj, &min, &rev, &suff);
  snprintf(pegasus__version, 99, "%d.%d.%d%s", maj, min, rev, suff);
  return pegasus__version;  
}

int pegasus_getcontextsize() 
{
  return( sizeof(pegasus_ctx_t) );
}

int pegasus_init(pegasus_conf_t* config)
{
  if (config->start_broker_cb == NULL ||
      config->minion_pool_size <= 0 ||
      (config->log_level < LOG_QUIET && !config->log_file))
    goto failure;

  pegasus__config = *config;
  pegasus__guid = 0;
  PEGASUS_LOGF(LOG_NOTICE, "Starting Pegasus %s", pegasus_strversion());

  pegasus__minions = malloc(config->minion_pool_size * sizeof(pegasus_minion_t));
  if (!pegasus__minions) {
    PEGASUS_LOGS(LOG_FATAL, "FATAL: could not allocate memory");
    goto failure;
  }

  pegasus__mq = malloc(config->minion_pool_size * sizeof(pegasus_minion_t*));
  if (!pegasus__mq) {
    PEGASUS_LOGS(LOG_FATAL, "FATAL: could not allocate memory");
    goto dealloc_minions;
  }

  if (pthread_mutex_init(&pegasus__mqmut, NULL) != 0) {
    PEGASUS_LOGS(LOG_FATAL, "FATAL: could not initialize mutex");
    goto dealloc_queue;
  }

  if (pthread_mutex_init(&pegasus__guidmut, NULL) != 0) {
    PEGASUS_LOGS( LOG_FATAL, "FATAL: could not initialize mutex");
    goto destroy_mqmut;
  }

  if (sem_init(&pegasus__mqsem, 0, config->minion_pool_size) != 0) {
    PEGASUS_LOGS(LOG_FATAL, "FATAL: could not initialize semaphore");
    goto destroy_guidmut;
  }

  if (prefork_minions(config->minion_pool_size) != 0)
   goto destroy_sem;

  int i;
  for (i = 0; i < config->minion_pool_size; ++i)
    pegasus__mq[i] = &pegasus__minions[i];
  pegasus__mqsz = config->minion_pool_size;

  return( 0 );

destroy_sem:
  sem_destroy(&pegasus__mqsem);

destroy_guidmut:
  pthread_mutex_destroy(&pegasus__guidmut);

destroy_mqmut:
  pthread_mutex_destroy(&pegasus__mqmut);

dealloc_queue:
  free(pegasus__mq);

dealloc_minions:
  free(pegasus__minions);

failure:
  return( -1 );
}

int pegasus_new_ctx(pegasus_ctx_t* ctx, byte* ctxdata)
{
  /* this locking mechanism seems completely at fault. there's
   * gotta be an easier way to achieve this but I'm not really
   * seeing it... */
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
    goto failure;
  }
  ts.tv_sec += pegasus__config.lock_timeout;

  if (sem_timedwait(&pegasus__mqsem, &ts) == -1) {
    goto failure;
  }
  PEGASUS_NONFAIL(pthread_mutex_lock(&pegasus__mqmut) == 0);

  if (pegasus__mqsz <= 0) {
    PEGASUS_LOGS(LOG_ERROR, "Since we managed to wait on the semaphore, there "
        "should be at least one free worker! (Failure, cannot create context)");
    goto failure;
  }

  pegasus_minion_t* minion = pegasus__mq[--pegasus__mqsz];
  PEGASUS_NONFAIL(pthread_mutex_unlock(&pegasus__mqmut) == 0);

  int res = minion_init(minion, ctxdata, &ctx->guid);
  if (res == -2) { /* minion in unstable state */
    goto recreate_minion;
  } else if (res == -1) { /* minion is stable but could not fullfill */
    goto release_minion;
  }

  ctx->minion = minion;
  PEGASUS_LOGS(LOG_DEBUG1, "Context created!");
  return( 0 );

recreate_minion:
  PEGASUS_LOGS(LOG_WARNING, "Minion in unstable state, we will recreate "
      "it and then fail to serve this connection");
  smite_minion(minion);
  minion->is_unstable = 0;
  if ((res = prefork_minion(minion)) != 0) {
    if (res == -1) {
      smite_minion(minion);
    }
    PEGASUS_LOGS(LOG_ERROR, "Could not recreate this minion! Resource "
        "depletion may occur without any way to countermand it");
    /*
     * - Self-destruct cannot be countermanded!
     * - I'm not looking for a countermand, dear... I'm looking for reverse.
     */
  } else {
    PEGASUS_LOGS(LOG_NOTICE, "Minion resurrected successfully");
  }

release_minion:
  PEGASUS_LOGS(LOG_NOTICE, "Giving back this minion for usage");

  PEGASUS_NONFAIL(pthread_mutex_lock(&pegasus__mqmut) == 0);
  pegasus__mq[pegasus__mqsz++] = minion;
  PEGASUS_NONFAIL(pthread_mutex_unlock(&pegasus__mqmut) == 0);
  PEGASUS_NONFAIL(sem_post(&pegasus__mqsem) == 0);

failure:
  return( -1 );
}

int pegasus_handle_message(pegasus_ctx_t* ctx, const byte* buf, length_t
      msglen, byte** response, length_t *resplen)
{
  pegasus_minion_t* min = ctx->minion;
  if (min->is_unstable) {
    PEGASUS_LOGF(LOG_WARNING, "Minion %ld is unstable, refusing to serve!", (long) min->pid);
    goto failure;
  }

  pegasus_req_hdr_t reqhdr;
  reqhdr.type = PEGASUS_REQ_HANDLE;

  pegasus_handle_req_t hreq;
  memcpy(hreq.guid.data, ctx->guid.data, sizeof(pegasus_guid_t));
  hreq.msgsize = msglen;
  
  if (!write_packet(min->fds[1], (byte*) &reqhdr, sizeof(pegasus_req_hdr_t)) ||
      !write_packet(min->fds[1], (byte*) &hreq, sizeof(pegasus_handle_req_t)) ||
      !write_packet(min->fds[1], buf, msglen)) {
    PEGASUS_LOGF(LOG_ERROR, "Unable to write handle request to minion %ld, unstable state, further calls will fail", (long) min->pid);
    goto set_unstable;
  }

  pegasus_resp_hdr_t resphdr;
  pegasus_handle_resp_t hresp;

  if (!read_packet(min->fds[0], (byte*) &resphdr, sizeof(pegasus_resp_hdr_t))) {
    PEGASUS_LOGF(LOG_WARNING, "Unable to read handle response header from minion %ld, unstable state, further calls will fail", (long) min->pid);
    goto set_unstable;
  }

  if (resphdr.type != PEGASUS_RESP_HANDLE_OK) {
    PEGASUS_LOGF(LOG_WARNING, "Minion %ld failed to serve request", (long)min->pid);
    goto failure;
  }

  if (!read_packet(min->fds[0], (byte*) &hresp, sizeof(pegasus_handle_resp_t))) {
    PEGASUS_LOGF(LOG_WARNING, "Unable to read handle response from minion %ld, unstable state, further calls will fail", (long) min->pid);
    goto set_unstable;
  }
  if (hresp.respsize > *resplen) {
    PEGASUS_LOGS(LOG_WARNING, "Response from minion too long, failing");
    goto failure;
  }
  *resplen = hresp.respsize;


  byte* respbuf = malloc(hresp.respsize + pegasus__config.buffer_sentinel);
  if (!respbuf) {
    PEGASUS_LOGS(LOG_ERROR, "Memory allocation failed, unstable state of minion, further calls will fail!");
    goto set_unstable;
  }

  if (!read_packet(min->fds[0], respbuf, hresp.respsize)) {
    PEGASUS_LOGF(LOG_WARNING, "Unable to read response data from minion %ld, unstable state, further calls will fail", (long) min->pid);
    goto dealloc_buffer;
  }
fprintf(stderr,"resp is %d\n", (int)*resplen);
  *response = respbuf;
  return( 0 );

dealloc_buffer:
  free(respbuf);

set_unstable:
  min->is_unstable = 1;

failure:
  return( -1 );
}

void pegasus_destroy_ctx(pegasus_ctx_t* ctx)
{
  minion_destroy(ctx->minion, ctx->guid);
  PEGASUS_NONFAIL(pthread_mutex_lock(&pegasus__mqmut) == 0);
  pegasus__mq[pegasus__mqsz++] = ctx->minion;
  PEGASUS_NONFAIL(pthread_mutex_unlock(&pegasus__mqmut) == 0);
  PEGASUS_NONFAIL(sem_post(&pegasus__mqsem) == 0);
}

void pegasus_cleanup()
{
  int i;
  for (i = 0; i < pegasus__config.minion_pool_size; ++i) {
    pid_t pid = pegasus__minions[i].pid;
    smite_minion(&pegasus__minions[i]);

    int dummy;
    waitpid(pid, &dummy, 0);
  }
}

int prefork_minion(pegasus_minion_t* min)
{
  int minionread[2], minionwrite[2];

  if (pipe(minionread) == -1) {
    return( -2 );
  }

  if (pipe(minionwrite) == -1) {
    close(minionread[0]);
    close(minionread[1]);

    return( -2 );
  }
  
  pid_t pid = fork();
  if (pid < 0) {
    close(minionread[0]);
    close(minionread[1]);

    close(minionwrite[0]);
    close(minionwrite[1]);

    return( -2 );
  } else if (pid == 0) {
    if (broker_surrogate(pid, minionwrite /* me2master */, minionread /* master2me */) != 0) {
      return( -1 );
    }
  } else {
    min->pid = pid;
    min->fds[0] = minionwrite[0]; /* record read end of minion-write */
    min->fds[1] = minionread[1]; /* record write end of minion-read */

    close(minionwrite[1]); /* close write end of minion-write */
    close(minionread[0]); /* close read end of minion-read */

    int err = -3;
    /* broker_surrogate writes an integer indicating if everything
     * went right, so we read it here */
    if (read(minionwrite[0], &err, sizeof(int)) != sizeof(int) ||
        err != 0) {
      PEGASUS_LOGF(LOG_ERROR, "Minion reported failure (err=%d)", err);
      return( -1 );
    }
  }
  return( 0 );
}

void smite_minion(pegasus_minion_t* min)
{
  if (kill(min->pid, SIGTERM) == -1)
    return;
  close(min->fds[0]);
  close(min->fds[1]);
}

int prefork_minions(int count)
{
  int i;
  PEGASUS_LOGF(LOG_NOTICE, "Preforking %d minions", count);
  for (i = 0; i < count; ++i) {
    pegasus_minion_t* min = &pegasus__minions[i];
    min->is_unstable = 0;
    int res = prefork_minion(min);
    if (res == -2)
      goto rollback_preforks;
    else if (res == -1) { 
      ++i; /* do the current one since it's been initialized and not cleaned up
              (HACKISH!) */
      goto rollback_preforks;
    }
  }

  return( 0 );

rollback_preforks:
  PEGASUS_LOGS(LOG_ERROR, "Minion initialization failure, rolling back");

  --i; /* don't do the current one! */
  for (; i >= 0; --i)
    smite_minion(&pegasus__minions[i]);

/* failure: */
  return( -1 );
}

int broker_surrogate(pid_t mypid, int me2master[2], int master2me[2])
{
  signal(SIGINT, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  close(me2master[0]); /* we don't want to read from our write pipe */
  close(master2me[1]); /* ...nor write to our read pipe */

  int err = 0;
  if (dup2(me2master[1], STDOUT_FILENO) == -1) {
    err = -1; 
  }

  if (dup2(master2me[0], STDIN_FILENO) == -1) {
    err = -2;
  }
  
  if (write(me2master[1], &err, sizeof(int)) != sizeof(int))
    return( -1 );

  if (err == 0) { /* everything OK */
    /* get the broker rolling */
    return( pegasus__config.start_broker_cb(pegasus__config.start_broker_cb_param) );
  } else return( -1 );
}

void minion_destroy(pegasus_minion_t* min, pegasus_guid_t guid)
{
  if (min->is_unstable)
    return ;
  pegasus_req_hdr_t hdr;
  pegasus_quit_req_t req;
  hdr.type = PEGASUS_REQ_QUIT;
  memcpy(req.guid.data, guid.data, PEGASUS_GUID_BYTES);

  if (!write_packet(min->fds[1], (byte*) &hdr, sizeof(pegasus_req_hdr_t)) ||
      !write_packet(min->fds[1], (byte*) &req, sizeof(pegasus_quit_req_t))) {
    PEGASUS_LOGF(LOG_WARNING, "Failed to send quit request to minion %ld, "
        "a subsequent init will fail", (long) min->pid);
    min->is_unstable = 1;
    return ;
  }

  pegasus_resp_hdr_t resphdr;
  if (!read_packet(min->fds[0], (byte*) &resphdr, sizeof(pegasus_resp_hdr_t))) {
    PEGASUS_LOGF(LOG_WARNING, "Failed to read quit response from minion %ld",
        (long) min->pid);
    min->is_unstable = 1;
    return ;
  }

  if (resphdr.type != PEGASUS_RESP_QUIT_OK)
    PEGASUS_LOGF(LOG_WARNING, "Something's wrong with the response type from "
        "minion %ld, a subsequent init may fail", (long) min->pid);
}

int minion_init(pegasus_minion_t* min, byte* mindata, pegasus_guid_t* opguid)
{
  if (min->is_unstable) {
    PEGASUS_LOGF(LOG_WARNING, "Minion %ld is unstable, refusing to init!", (long) min->pid);
    return( -2 );
  }

  pegasus_req_hdr_t hdr;
  pegasus_start_req_t req;
  hdr.type = PEGASUS_REQ_START;
  req.datasize = pegasus__config.context_data_length;

  PEGASUS_NONFAIL(pthread_mutex_lock(&pegasus__guidmut) == 0);
  memcpy(req.guid.data, &pegasus__guid, PEGASUS_GUID_BYTES);
  memcpy(opguid->data, &pegasus__guid, PEGASUS_GUID_BYTES);
  ++pegasus__guid;
  PEGASUS_NONFAIL(pthread_mutex_unlock(&pegasus__guidmut) == 0);

  if (!write_packet(min->fds[1], (byte*) &hdr, sizeof(pegasus_req_hdr_t)) ||
      !write_packet(min->fds[1], (byte*) &req, sizeof(pegasus_start_req_t)) || 
      !write_packet(min->fds[1], mindata, pegasus__config.context_data_length)) {
    PEGASUS_LOGF(LOG_WARNING, "Could not write start request to minion %ld, "
        "unstable state!", (long) min->pid);
    return( -2 );
  }

  pegasus_resp_hdr_t resphdr;
  if (!read_packet(min->fds[0], (byte*) &resphdr, sizeof(pegasus_resp_hdr_t))) {
    PEGASUS_LOGF(LOG_WARNING, "Could not read start response from minion %ld, "
        "unstable state!", (long) min->pid);
    return( -2 );
  }

  if (resphdr.type != PEGASUS_RESP_START_OK) {
    PEGASUS_LOGF(LOG_WARNING, "Start failed on minion %ld", (long) min->pid);
    return( -1 );
  }
  union {
    uint64_t u64;
    pegasus_guid_t guid;
  } guidcast;
  guidcast.guid = *opguid;

  PEGASUS_LOGF(LOG_DEBUG1, "Minion %ld awakened to serve request (GUID=%" 
      PRIu64 ")", (long) min->pid, guidcast.u64);
  return( 0 );
}

int read_packet(int fd, byte* buffer, length_t packetlen)
{
  length_t pread = 0;
  slength_t this_read = 0;
  int selret;

  struct timeval tv;
  fd_set fds;

  do {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv = pegasus__config.message_timeout;

    selret = select(fd + 1, &fds, NULL, NULL, &tv);
    if (selret <= 0)
      return( 0 ); /* timed out or error ocurred */

    this_read = read(fd, buffer + pread, packetlen - pread);
  } while (this_read > 0 && (pread += this_read) < packetlen);
  return (pread == packetlen);
}

int write_packet(int fd, const byte* buffer, length_t packetlen)
{
  return (write(fd, buffer, packetlen) == packetlen);
}  


/** End Pegasus public interface **/

