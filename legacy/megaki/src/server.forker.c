#include "common.h"
#include "threadpool.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#define MAGIC_BYTES         6
#define RSA_LIMIT           (MEGAKI_RSA_KEYSIZE / 8 - 42)
#define SOCKET_BACKLOG      512
#define QUEUE_BACKLOG       8192
#define CONFIG_MAXLINESIZE  16384
#define MAX_THREADS         4096
#define MAX_ARG_LENGTH      16384
#define RECEIVE_TIMEOUT     30
#define RECEIVE_FLAGS       (0)
#define SYN_LENGTH_NOHEAD   (MEGAKI_HASH_BYTES + 2 * MEGAKI_RSA_KEYSIZE / 8)

#define MAX_MESSAGE_LENGTH   1024
#define DECRYPTION_BUF_LENGTH 512
int opt_daemonize;

char* opt_port, *opt_addr, *opt_cert, *opt_cert_passphrase;
int listen_socket, opt_threads;

RSA * server_private;

typedef struct queue_elem {
  int socket;
  struct sockaddr* claddr;
  socklen_t claddr_len;
} queue_elem;


struct timeval tv;  
  
queue_elem queue[ QUEUE_BACKLOG ]; /* 1,5 MB */
int queue_size, should_shutdown;
pthread_t threads[ MAX_THREADS ];
pthread_mutex_t queue_mutex;

void quit_connection(int connsocket, int ret)
{
  shutdown(connsocket, SHUT_RDWR);
}

void handle_connection(int connsocket, struct sockaddr* claddr, socklen_t claddr_size)
{
  setsockopt(connsocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
  
  byte buffer[MAX_MESSAGE_LENGTH], decbuffer[DECRYPTION_BUF_LENGTH], mac[MEGAKI_HASH_BYTES];
  if (recv(connsocket, buffer, MAGIC_BYTES, RECEIVE_FLAGS) < MAGIC_BYTES)
    quit_connection(connsocket, 0);
    
  RSA * client_public;
  magic_type mgt;
  mgt = mgk_check_magic(buffer);
  if (mgt == magic_syn) {
    /* decode the syn packet */
    if (recv(connsocket, buffer, SYN_LENGTH_NOHEAD, RECEIVE_FLAGS) < SYN_LENGTH_NOHEAD)
      quit_connection(connsocket, 0);
    
    int recovered;
    /* decrypt block 1 */
    if ((recovered = RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES, decbuffer,
        server_private, RSA_PKCS1_OAEP_PADDING)) == -1)
      quit_connection(connsocket, 0);
    
    /* decrypt block 2 */
    if (RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES + MEGAKI_RSA_KEYSIZE / 8,
        decbuffer + recovered, server_private, RSA_PKCS1_OAEP_PADDING) == -1)
      quit_connection(connsocket, 0);
    
    /* decode block 2 */
    int i;
    for (i = 0; i < recovered; ++i)
      decbuffer[i + recovered] ^= decbuffer[i];
      
    /* compute MAC and check */
    SHA256(decbuffer, MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES, mac);
    if (!mgk_memeql(mac, buffer, MEGAKI_HASH_BYTES))
      quit_connection(connsocket, 0);
    
    /* fill client public key data */
    client_public = RSA_new();
    if (client_public == NULL)
      quit_connection(connsocket, -1);
      
    if (!(client_public->n = BN_bin2bn(decbuffer, MEGAKI_RSA_KEYSIZE / 8, client_public->n)))
      quit_connection(connsocket, -1);
      
    if (!(client_public->e = BN_bin2bn(decbuffer, 4, client_public->e)))
      quit_connection(connsocket, -1);
      
    
    
  } else if (mgt == magic_restart) {
    
  } else quit_connection(connsocket, 0);
  
  quit_connection(connsocket, 0);
}

int server()
{
  int res, child_socket, status;
  struct addrinfo hints, *result, *ptr;  
  struct sockaddr claddr;
  socklen_t claddr_size;
  
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  
  res = getaddrinfo(opt_addr, opt_port, &hints, &result);
  if (res != 0) {
    fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(res));
    return(-1);
  }
  
  for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
    listen_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    int a = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &a, sizeof(a));
  
    if (listen_socket != -1) {
      if (bind(listen_socket, ptr->ai_addr, ptr->ai_addrlen) != -1)
        break;
      else {
        perror("bind()");
        close(listen_socket);
      }
    }
    else perror("socket()");
  }
  
  if (ptr == NULL) {
    fprintf(stderr, "fatal: could not bind to any addresses\n");
    return(-1);
  }
  
  if (listen(listen_socket, SOCKET_BACKLOG) == -1) {
    perror("listen()");
    return(-1);
  }
  
  
  fprintf(stderr, "bound and listening on %s:%s\n", opt_addr, opt_port);
  while (1) {
    child_socket = accept(listen_socket, &claddr, &claddr_size);
    if (fork() == 0) {
      handle_connection(child_socket, &claddr, claddr_size);
      exit(0);
    }
  }
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
      opt_addr = right;
    } else if (!strcmp(left, "port")) {
      opt_port = right;
    } else if (!strcmp(left, "daemonize")) {
      opt_daemonize = atoi(right);
    } else if (!strcmp(left, "cert")) {
      opt_cert = right;
    } else if (!strcmp(left, "cert-passphrase")) {
      opt_cert_passphrase = right;
    } else if (!strcmp(left, "threads")) {
      opt_threads = atoi(right);
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
        
        fclose(conf);
      }
    } else {
      fprintf(stderr, "Unknown option: %s\n", left);
      return;
    }
  }
  return;
}

void defaults()
{
  opt_daemonize = 1;
  opt_threads = 10;
}

int main(int argc, char** argv)
{
  char** arg;
  
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();
  
  for (arg = argv + 1; arg < argv + argc; ++arg) {
    process_option(*arg, 1);
  }
  
  tv.tv_sec = RECEIVE_TIMEOUT;
  tv.tv_usec = 0;
  
  if (!opt_cert) {
    fprintf(stderr, "fatal: no certificate provided\n");
    return(-1);
  }
  
  FILE * f = fopen(opt_cert, "r");
  if (!f) {
    fprintf(stderr, "fatal: could not open certificate file '%s' for reading\n", opt_cert);
    return(-1);
  }
  
  if (PEM_read_RSAPrivateKey(f, &server_private, NULL, opt_cert_passphrase) == NULL) {
    fprintf(stderr, "fatal: failed reading PEM file: %s\n", ERR_reason_error_string(ERR_get_error()));
    return(-1);
  }
  
  threadpool_t * pool;
  pool = threadpool_create(opt_threads, QUEUE_BACKLOG, 0);
  if (pool == NULL) {
    fprintf(stderr, "fatal: could not create threadpool\n");
    return(-1);
  }
  fprintf(stderr, "created threadpool of %d threads with a queue of %d\n",
    opt_threads, QUEUE_BACKLOG);
    
  if (opt_daemonize) {
    if (fork() == 0) {
      return( server() );
    } else {
      return(0);
    }
  } else {
    return( server() );
  }
}

