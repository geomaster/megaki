#include <stdio.h>
#include "client.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#define MEGAKI_RSA_KEYSIZE 2048

char randomness[] = 
  "Ze quick brown fox jumps over the lazy dog. Yabbabdddbababababab"
  "dgfhdlghkjghkjdfghkjdfhgkjdghkjdfhgkjhdfkgjdhfgjkhdfkghdkfjhgjkh"
  "lfkjdlfkgk  sfjadkflasfkdfjkfdjk\ndkljfdklhjkldfjgklDSjf\t"
  "fkljghkglgkgkgkgkk2kkk3kk8k8k8k8k9000300303030300";
  
byte buf[1000];

struct mgk_serverauth {
  /* Server public key (n, e) */
  byte modulus[MEGAKI_RSA_KEYSIZE / 8];
  int32_t exponent;
};

main()
{
  mgk_rand_seed(randomness, sizeof(randomness));
  mgk_clientctx *ctx;
  mgk_serverauth srv;
  
            struct addrinfo hints;
           struct addrinfo *result, *rp;
           int sfd, s, j;
           size_t len;
           ssize_t nread;

           /* Obtain address(es) matching host/port */

           memset(&hints, 0, sizeof(struct addrinfo));
           hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
           hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
           hints.ai_flags = 0;
           hints.ai_protocol = 0;          /* Any protocol */

           s = getaddrinfo("127.0.0.1", "6363", &hints, &result);
           if (s != 0) {
               fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
               exit(EXIT_FAILURE);
           }

           /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */


           for (rp = result; rp != NULL; rp = rp->ai_next) {
               sfd = socket(rp->ai_family, rp->ai_socktype,
                            rp->ai_protocol);
               if (sfd == -1)
                   continue;

               if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
                   break;                  /* Success */

               close(sfd);
           }

           if (rp == NULL) {               /* No address succeeded */
               fprintf(stderr, "Could not connect\n");
               exit(EXIT_FAILURE);
           }

           freeaddrinfo(result);           /* No longer needed */

  RSA * server_pub = NULL;
  
  FILE* f = fopen("server-public.pub", "r");
  ERR_load_crypto_strings();
  if (!f || PEM_read_RSA_PUBKEY(f, &server_pub, NULL, NULL) == NULL) {
    fprintf(stderr, "Could not read key\n");
    fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));
    exit(-1);
  }
  fclose(f);
  
  BN_bn2bin(server_pub->n, srv.modulus);
  srv.exponent = 65537;
  
if (!mgk_init_client_ctx(&ctx, &srv)) {
    fprintf(stderr, "sdfhdfjkhNOOOOOOOOO\n");
    return(-1);;
  }
  
  length_t l = 1000;
  if (!mgk_build_syn(ctx, buf, &l)) {
    fprintf(stderr, "err. this should not happen\n");
    return(-1);
  }
  
  //write(STDOUT_FILENO, buf, l/*, 0*/);
  send(sfd, buf, l,0);
  //read(STDIN_FILENO, buf, 550);
  //send(sfd, buf, 550, 0);
  //sleep(1);
  //close(sfd);
  //return(0);
  memset(buf, 0, 310);
  int rec = recv(sfd, buf, 310, MSG_WAITALL);
  printf("i got %d\n", rec);
  if (!mgk_decode_synack(ctx, buf, 310)) {
    fprintf(stderr, "whoopsies.\n");
    return(-1);
  }
  
  if (!mgk_build_ack(ctx, buf, &l)) {
    fprintf(stderr, "nisam bio mnogo jak da odolim na tvoj tajni znak\n");
    return(-1);
  }
  send(sfd, buf, l, 0);
  recv(sfd, buf, 6, MSG_WAITALL);
/*  char ss[]="1234567890ab";*/
buf[0]='M';buf[1]='G';buf[2]='K';buf[3]=0xEA;buf[4]=0xCA;buf[5]=0x04;
  uint32_t a = htonl(10);
  memcpy(buf+6,&a,sizeof(a));
  send(sfd, buf, 10, 0);

while(1);
  shutdown(sfd,SHUT_RDWR);  
  mgk_destroy_client_ctx(&ctx);
  EVP_cleanup();
  ERR_free_strings();
  CRYPTO_cleanup_all_ex_data();
  usleep(2);
  return(0);
}
