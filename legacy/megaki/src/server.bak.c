#include "common.h"
#include "threadpool.h"
#include "tokenbank.h"
#include "hexdump.h"
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#define DOCUMENT_CONNECTIONS

#define MAGIC_BYTES               6
#define RSA_LIMIT                 (MEGAKI_RSA_KEYSIZE / 8 - 42)
#define SOCKET_BACKLOG            2048
#define QUEUE_BACKLOG             8192
#define CONFIG_MAXLINESIZE        16384
#define MAX_THREADS               4096
#define MAX_ARG_LENGTH            16384

#define RECEIVE_TIMEOUT           30
#define RECEIVE_FLAGS             (MSG_WAITALL)
#define SEND_FLAGS                (0)
#define SYN_LENGTH_NOHEAD         (MEGAKI_HASH_BYTES + 2 * MEGAKI_RSA_KEYSIZE / 8)
#define SYNACK_LENGTH_NOHEAD      (MEGAKI_TOKEN_BYTES + MEGAKI_HASH_BYTES + 
#define MAX_TOKENS                100
#define LINGER_SECONDS            10
#define MAX_TOKEN_BUCKETS         (2*MAX_TOKENS)

#define MAX_MESSAGE_LENGTH        1024
#define DECRYPTION_BUF_LENGTH     512

#define MAX_CONNECTIONS           
int opt_daemonize;

char* opt_port, *opt_addr, *opt_cert, *opt_cert_passphrase;
int last_elem, listen_socket, opt_threads, opt_queuelength;

threadpool_t * pool;
  
RSA * server_private;

typedef struct worker_info {
  int socket;
  struct sockaddr* claddr;
  socklen_t claddr_size;
} worker_info;

worker_info *workers;

struct timeval tv;  
struct linger lin;

void quit_connection(int connsocket, int ret)
{
  shutdown(connsocket, SHUT_RDWR);
  close(connsocket);
}

void onexit()
{
  fprintf(stderr, "stopping threadpool\n");
  threadpool_destroy(pool, 0);
  fprintf(stderr, "threadpool destroyed, shutting down\n");
}

const char vowels[] = "AEIOU";
const char consonants[] = "BCDFGHJKLMNPQRSTVWXYZ";

void open_connection(int connsocket, struct sockaddr* claddr, socklen_t claddr_size)
{
  
}

void handle_connection(int connsocket, struct sockaddr* claddr, socklen_t claddr_size)
{
  setsockopt(connsocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
  setsockopt(connsocket, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));

  byte buffer[MAX_MESSAGE_LENGTH], decbuffer[DECRYPTION_BUF_LENGTH], mac[MEGAKI_HASH_BYTES],
       tokstr[MEGAKI_TOKEN_BYTES];
       
  #ifdef DOCUMENT_CONNECTIONS
  char cons[7];
  int consi;
  for (consi = 0; consi < 6; ++consi) {
    if (consi % 2 == 0)
      cons[consi] = consonants[rand() % (sizeof consonants - 1)];
    else cons[consi] = vowels[rand() % (sizeof vowels - 1)];
  }
  cons[6] = '\0';
  
  fprintf(stderr, "[%s] opening connection\n", cons);
  #endif
  
  if (recv(connsocket, buffer, MAGIC_BYTES, RECEIVE_FLAGS) < MAGIC_BYTES) {
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] unexpected eof before magic\n", cons);
    #endif
    
    quit_connection(connsocket, 0);
    return;
  }
    
  RSA * client_public;
  magic_type mgt;
  tokentry* token;
  mgt = mgk_check_magic(buffer);
  if (mgt == magic_syn) {
    /* receive the syn packet */
    if (recv(connsocket, buffer, SYN_LENGTH_NOHEAD, RECEIVE_FLAGS) < SYN_LENGTH_NOHEAD) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] unexpected eof before syn packet was received\n", cons);
      #endif
      quit_connection(connsocket, 0);
      return;
    }
    
    int recovered;
    /* decrypt block 1 */
    if ((recovered = RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES, decbuffer,
        server_private, RSA_PKCS1_OAEP_PADDING)) == -1) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] could not decrypt block 1 of syn ciphertext:\n\t", cons);
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "\n");
      #endif

      quit_connection(connsocket, 0);
      return;
    }
    
    /* decrypt block 2 */
    if (RSA_private_decrypt(MEGAKI_RSA_KEYSIZE / 8, buffer + MEGAKI_HASH_BYTES + MEGAKI_RSA_KEYSIZE / 8,
        decbuffer + recovered, server_private, RSA_PKCS1_OAEP_PADDING) == -1) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] could not decrypt block 2 of syn ciphertext:\n\t", cons);
      ERR_print_errors_fp(stderr);
      fprintf(stderr, "\n");
      #endif
      quit_connection(connsocket, 0);
      return;
    }
    
    /* decode block 2 */
    int i;
    for (i = 0; i < recovered; ++i)
      decbuffer[i + recovered] ^= decbuffer[i];
    
    #ifdef DOCUMENT_CONNECTIONS
    fprintf(stderr, "[%s] syn plaintext:\n", cons);
    hexdump(stderr, "SYNCLRT", decbuffer, MEGAKI_VERSION_BYTES + 4 + MEGAKI_RSA_KEYSIZE / 8);
    printf("\n");
    #endif
    
    /* compute MAC and check */
    SHA256(decbuffer, MEGAKI_RSA_KEYSIZE / 8 + 4 + MEGAKI_VERSION_BYTES, mac);
    if (!mgk_memeql(mac, buffer, MEGAKI_HASH_BYTES)) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] hash mismatch in syn packet\n", cons);
      #endif
      quit_connection(connsocket, 0);
      return;
    }
    
    /* fill client public key data */
    client_public = RSA_new();
    if (client_public == NULL) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: RSA alloc fails\n", cons);
      #endif
      quit_connection(connsocket, -1);
      return;
    }
      
    if (!(client_public->n = BN_bin2bn(decbuffer, MEGAKI_RSA_KEYSIZE / 8, client_public->n))) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: BN_bin2bn fails on modulus\n", cons);
      #endif
      quit_connection(connsocket, -1);
      return;
    }
      
    if (!(client_public->e = BN_bin2bn(decbuffer + MEGAKI_RSA_KEYSIZE / 8, 4, client_public->e))) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] UNEXPECTED: BN_bin2bn fails on exponent\n", cons);
      #endif
      quit_connection(connsocket, -1);
      return;
    }
    
    #ifdef DOCUMENT_CONNECTIONS
    byte debugbuf[MEGAKI_RSA_KEYSIZE / 8];
    BN_bn2bin(client_public->n, debugbuf);
    fprintf(stderr, "[%s] retrieved client modulus/exponent:\n", cons);
    hexdump(stderr, "CLNTMOD", debugbuf, BN_num_bytes(client_public->n));
    BN_bn2bin(client_public->e, debugbuf);
    hexdump(stderr, "CLNTEXP", debugbuf, BN_num_bytes(client_public->e));
    fprintf(stderr, "\n");
    #endif
    
    int badproto = 0, internalerror = 0;
    const int off = MEGAKI_RSA_KEYSIZE / 8 + 4;
    /* check the version first */
    if (memcmp(MEGAKI_VERSION, decbuffer + off, MEGAKI_VERSION_BYTES) != 0) {
      /* we're not running the same version of the protocol---sorry pal */
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] version mismatch, client uses %02X%02X and we're on %02X%02X\n", cons,
        decbuffer[off], decbuffer[off + 1],
        MEGAKI_VERSION[0], MEGAKI_VERSION[1]);
      #endif
      badproto = 1;
    }
    
    /* so, the client has taken care to do an RSA pad-encrypt operation
     * and to compute an SHA-256 hash. maybe she is worth our time...? */
    mgk_fill_magic(buffer, magic_synack);
    if (badproto) {
      memcpy(decbuffer, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES);
      memcpy(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_INCOMPATIBLE_VERSIONS_ERROR, MEGAKI_ERROR_CODE_BYTES);
    } else {
      if (!RAND_pseudo_bytes(tokstr, MEGAKI_TOKEN_BYTES)) {
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] UNEXPECTED: could not generate bytes for token\n", cons);
        #endif
        quit_connection(connsocket, -1);
        return;
      }
      
      token = tok_create(tokstr);
      if (!token) {
        memcpy(decbuffer, MEGAKI_ERROR_TOKEN, MEGAKI_TOKEN_BYTES);    
        memcpy(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_SERVICE_UNAVAILABLE_ERROR, MEGAKI_ERROR_CODE_BYTES);    
        
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] UNEXPECTED: tok_create fails\n", cons);
        #endif
        internalerror = 1;
      } else {
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] generated token:\n", cons);
        hexdump(stderr, "SSTOKEN", tokstr, MEGAKI_TOKEN_BYTES);
        #endif
        memcpy(decbuffer, token->token, MEGAKI_TOKEN_BYTES);
        memcpy(buffer + MAGIC_BYTES + MEGAKI_HASH_BYTES, token->token, MEGAKI_TOKEN_BYTES);
        
        if (!RAND_bytes(decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_RSA_KEYSIZE / 8)) {
          #ifdef DOCUMENT_CONNECTIONS
          fprintf(stderr, "[%s] UNEXPECTED: could not generate bytes for srvsymm\n", cons);
          #endif
          quit_connection(connsocket, -1);
          return;
        }
        #ifdef DOCUMENT_CONNECTIONS
        fprintf(stderr, "[%s] generated srvsymm:\n", cons);
        hexdump(stderr, "SRVSYMM", decbuffer + MEGAKI_TOKEN_BYTES, MEGAKI_AES_CBC_KEYSIZE / 8);
        #endif
        
        SHA256(decbuffer, MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8, buffer + MAGIC_BYTES);
        
        if ((RSA_public_encrypt(MEGAKI_TOKEN_BYTES + MEGAKI_AES_CBC_KEYSIZE / 8, decbuffer,
          buffer + MAGIC_BYTES + MEGAKI_TOKEN_BYTES + MEGAKI_HASH_BYTES, client_public, RSA_PKCS1_OAEP_PADDING)) == -1) {
          #ifdef DOCUMENT_CONNECTIONS
          fprintf(stderr, "[%s] UNEXPECTED: could not encrypt syn-ack plaintext\n", cons);
          #endif
          quit_connection(connsocket, -1);
          return;
        }
      } 
    }
    const int len = MAGIC_BYTES + MEGAKI_HASH_BYTES + MEGAKI_TOKEN_BYTES +
    MEGAKI_RSA_KEYSIZE / 8;
    if (send(connsocket, buffer, len, SEND_FLAGS) < len) {
      quit_connection(connsocket, 0);
      return;
    }
    
    /* receive ack packet */
    if (recv(connsocket, buffer, SYNACK_LENGTH_NOHEAD, RECEIVE_FLAGS) < SYNACK_LENGTH_NOHEAD) {
      #ifdef DOCUMENT_CONNECTIONS
      fprintf(stderr, "[%s] unexpected eof before synack packet was received\n", cons);
      #endif
      quit_connection(connsocket, 0);
      return;
    }
    
    if (!
  } else if (mgt == magic_restart) {
    
  } else {
    quit_connection(connsocket, 0);
    return;
  }
  
  quit_connection(connsocket, 0);
}

void worker_main(void* param)
{
  /*worker_info* info = (worker_info*)param;*/
  handle_connection((int)param, NULL, 0);
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
    workers[last_elem].socket = child_socket;
    threadpool_add(pool, worker_main, (void*)child_socket, 0);
    last_elem = (last_elem + 1) % opt_queuelength;
  }
}

void handle_signal(int s) {
  onexit();
  exit(0);
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
    } else if (!strcmp(left, "queue-length")) {
      opt_queuelength = atoi(right);
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
  opt_queuelength = 40;
}

int main(int argc, char** argv)
{
  /*
  printf("testing token bank\n");
  tokinit();
  
  byte sth[MEGAKI_TOKEN_BYTES];
  tokentry* tokens[256];
  memset(sth, 0, MEGAKI_TOKEN_BYTES);
  int i;
  for (i = 0; i < 128; ++i) {
    sth[0] = i;
    int j = 10000000;
    while (j--);
    printf("byte %x\n", i);
    tokens[i] = tok_create(sth);
  }
  
  for (i = 255; i >= 128; --i) {
    sth[0] = i;
    int j = 10000000;
    while (j--);
    printf("byte %x\n", i);
    tokens[i] = tok_create(sth);
  }
  
  int i2 = 1;
  int j = 70000000 ;
  while(j--) i2 = 2 * i2 + 655 + j;
  
  for (i = 0; i < 254; ++i) {
    sth[0] = i;
    assert(tok_renew(sth) == tokens[i]);
  }
  
  return(0);*/
  char** arg;
  
  ERR_load_crypto_strings();
  OpenSSL_add_all_ciphers();
  if (!tokinit(MAX_TOKENS, MAX_TOKEN_BUCKETS)) {
    fprintf(stderr, "fatal: could not load the token bank\n");
    exit(-1);
  }
  
  defaults();
  for (arg = argv + 1; arg < argv + argc; ++arg) {
    process_option(*arg, 1);
  }
  
  tv.tv_sec = RECEIVE_TIMEOUT;
  tv.tv_usec = 0;
  
  lin.l_onoff = 1;
  lin.l_linger = LINGER_SECONDS;
  
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
  
  atexit(onexit);
  pool = threadpool_create(opt_threads, opt_queuelength, 0);
  if (pool == NULL) {
    fprintf(stderr, "fatal: could not create threadpool\n");
    return(-1);
  }
  fprintf(stderr, "created threadpool of %d threads with a queue of %d\n",
    opt_threads, opt_queuelength);
  workers = (worker_info*)malloc(sizeof(worker_info) * opt_queuelength);
  if (workers == NULL) {
    /* oh shit */
    fprintf(stderr, "fatal: memory allocation failed. we shall not continue\n");
    return(-1);
  }
  last_elem = 0;

  srand(time(NULL));
  
  struct sigaction siginth;  
  siginth.sa_handler = handle_signal;
  sigemptyset(&siginth.sa_mask);
  siginth.sa_flags = 0;
  /*sigaction(SIGINT, &siginth, NULL);*/
  
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

