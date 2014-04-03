#include "common.h"
#include "threadpool.h"
#include "hexdump.h"
#include "sslc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#define LIBUV_BUFFER_BYTES              131072
#define SOCKET_BACKLOG                  1024
#define MAX_ARG_LENGTH                  16384
#define CONFIG_MAXLINESIZE              (MAX_ARG_LENGTH * 2)

/** Forward declarations **/
void        defaults ();
void        handle_signal (int s);
int         main (int argc, char** argv);
void        process_option (char* s, int allow_config);
int         server ();

/***** Callbacks for libuv *****/
void        on_connect (uv_connect_t* req, int status);

/***** End callbacks for libuv *****/

/** End forward declarations **/

/** Options **/
int g_opt_daemonize, g_opt_threads, g_opt_queuelength;
char* g_opt_port, *g_opt_addr, *g_opt_cert, *g_opt_cert_passphrase;
/** End options **/

/** libuv globals **/
uv_g_loop_t* g_loop;
uv_tcp_t g_servconn;
threadpool_t * g_pool;

byte uvbuf[LIBUV_BUFFER_BYTES];
/** End libuv globals **/

/** Server globals **/
RSA * g_server_private;
/** End server globals **/

#define CHECK(res, reason) \
  if ((res) != 0) { \
    fprintf(stderr, "fatal: %s (%s)\n", (reason), uv_strerror(res)); \
    return(-1); \
  }
  
/** Log levels **/
enum log_level {
  ll_debug,
  ll_notice,
  ll_warning,
  ll_error,
  ll_fatal
};

#define LOG(level, 
void on_connect
int server()
{
  int res;
  g_loop = uv_default_loop();
  
  struct sockaddr_in addr;
  res = uv_ip4_addr(g_opt_addr, atoi(g_opt_port), &addr);
  if (res != 0) {
    fprintf(stderr, "fatal: could not resolve local address %s:%d (%s)\n", g_opt_addr, atoi(g_opt_port), uv_strerror(res));
    return(-1);
  }
  
  g_pool = threadpool_create(g_opt_threads, g_opt_queuelength, 0);
  if (g_pool == NULL) {
    fprintf(stderr, "fatal: could not create threadpool\n");
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    return(-1);
  }
  fprintf(stderr, "created threadpool of %d threads with a queue of %d\n",
    g_opt_threads, g_opt_queuelength);
  
  ssl_thread_setup();
  
  res = uv_tcp_init(g_loop, &g_servconn);
  CHECK(res, "could not init libuv tcp");
  res = uv_tcp_bind(&g_servconn, (struct sockaddr*)&addr, 0);
  CHECK(res, "could not bind to local address");

  res = uv_listen((uv_stream_t*)&g_servconn, SOCKET_BACKLOG, on_connect);
  CHECK(res, "could not listen for connections");
  
  fprintf(stderr, "bound and listening on %s:%s\n", g_opt_addr, g_opt_port);
  res = uv_run(g_loop, UV_RUN_DEFAULT);
  threadpool_destroy(g_pool, 0);  
  uv_loop_delete(g_loop);
  
  if (g_opt_port)
    free(g_opt_port);
  if (g_opt_addr)
    free(g_opt_addr);
  if (g_opt_cert)
    free(g_opt_cert);
  if (g_opt_cert_passphrase)
    free(g_opt_cert_passphrase);
  RSA_free(g_server_private);
  ssl_thread_cleanup();
  EVP_cleanup();
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
  
  return(res);
}

void handle_signal(int s) {
  
  fprintf(stderr, "received termination signal, quitting\n");
  onexit();
  return;
}

void process_option(char* s, int allow_config)
{
  char *left, *right, *p, *p1, *p2;
  size_t len, mode = 0;
  FILE * conf;
  
  len = strlen(s);
  if (len <= MAX_ARG_LENGTH) {
    left = (char*)malloc((len + 1) * sizeof(char));
    right = (char*)malloc((len + 1) * sizeof(char));
    
    if (left == NULL || right == NULL) {
      fprintf(stderr, "fatal: memory allocation failed. we shall not continue\n");
      exit(-1);
    }
    
    p1 = left;
    p2 = right;
    
    memset(left, 0, (len + 1) * sizeof(char));
    memset(right, 0, (len + 1) * sizeof(char));
    
    mode = 0;
    for (p = s; *p; ++p) {
      if (mode == 0 && *p == '=')
        mode = 1;
      else {
        if (mode == 0) 
          *p1++ = *p;
        else
          *p2++ = *p;
      }
    }
    
    len = strlen(left);
    if (!strcmp(left, "addr")) {
      g_opt_addr = right;
    } else if (!strcmp(left, "port")) {
      g_opt_port = right;
    } else if (!strcmp(left, "daemonize")) {
      g_opt_daemonize = atoi(right);
      free(right);
    } else if (!strcmp(left, "cert")) {
      g_opt_cert = right;
    } else if (!strcmp(left, "cert-passphrase")) {
      g_opt_cert_passphrase = right;
    } else if (!strcmp(left, "threads")) {
      g_opt_threads = atoi(right);
      free(right);
    } else if (!strcmp(left, "queue-length")) {
      g_opt_queuelength = atoi(right);
      free(right);
    } else if (allow_config && !strcmp(left, "config")) {
      conf = fopen(right, "r");
      if (!conf) {
        perror("fopen()");
        fprintf(stderr, "could not open config file\n");
      } else {
        char line[CONFIG_MAXLINESIZE];
        
        while (!feof(conf)) {
          memset(line, 0, sizeof(line));
          fgets(line, CONFIG_MAXLINESIZE * sizeof(char), conf);
          len = strlen(line);
          
          if (len) {
            line[len - 1] = '\0';
            process_option(line, 0);
          }
        }
        free(right);
        fclose(conf);
      }
    } else {
      fprintf(stderr, "Unknown option: %s\n", left);
      free(right);
      return;
    }
    free(left);
  }
  
  return;
}

void defaults()
{
  g_opt_daemonize = 1;
  g_opt_threads = 10;
  g_opt_queuelength = 40;
  g_opt_cert = g_opt_cert_passphrase = NULL;
}

int main(int argc, char** argv)
{
  char** arg;
  
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();

  defaults();
  for (arg = argv + 1; arg < argv + argc; ++arg) {
    process_option(*arg, 1);
  }
  
  if (!g_opt_cert) {
    fprintf(stderr, "fatal: no certificate provided\n");
    return(-1);
  }
  
  FILE * f = fopen(g_opt_cert, "r");
  if (!f) {
    fprintf(stderr, "fatal: could not open certificate file '%s' for reading\n", g_opt_cert);
    return(-1);
  }
  
  if (PEM_read_RSAPrivateKey(f, &g_server_private, NULL, g_opt_cert_passphrase) == NULL) {
    fprintf(stderr, "fatal: failed reading PEM file: %s\n", ERR_reason_error_string(ERR_get_error()));
    return(-1);
  }
  fclose(f);
  
  srand(time(NULL));
  
  struct sigaction siginth;  
  siginth.sa_handler = handle_signal;
  sigemptyset(&siginth.sa_mask);
  siginth.sa_flags = 0;
  sigaction(SIGINT, &siginth, NULL);
  
  if (g_opt_daemonize) {
    if (fork() == 0) {
      return( server() );
    } else {
      return(0);
    }
  } else {
    return( server() );
  }
}

