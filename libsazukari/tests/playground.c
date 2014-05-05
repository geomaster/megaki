#include <stdio.h>
#include <sazukari.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/pem.h>

slength_t writecb(byte* buf, length_t len, void* param)
{
  int sockfd = *(int*)(param);
  return write(sockfd, buf, len);
}

slength_t readcb(byte* buf, length_t len, void* param)
{
  int sockfd = *(int*)(param);
  return recv(sockfd, buf, len, 0);
}

szkr_iostream_t ios;
szkr_srvkey_t srvkey;
int main(int argc, char** argv)
{
  szkr_init();
  int sfd, s, j;
  OpenSSL_add_all_ciphers();

  struct addrinfo hints;
  struct addrinfo *result, *rp;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  s = getaddrinfo("127.0.0.1", "6363", &hints, &result);
  for (rp = result; rp; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;
    close(sfd);
  }


  int sz = szkr_get_ctxsize();
  szkr_ctx_t* ctx = (szkr_ctx_t*) malloc(sz);
  ios.read_callback = &readcb;
  ios.write_callback = &writecb;
  ios.cb_param = &sfd;

  byte*stuff = malloc(32768);
  int i;
  for (i = 0; i < 64; ++i)
    stuff[i] = (i % 10) + '0';

  RSA* srv = RSA_new();
  FILE* f = fopen("server.pub", "r");
  PEM_read_RSA_PUBKEY(f, &srv, NULL, "");
  BN_bn2bin(srv->n, srvkey.modulus);
  BN_bn2bin(srv->e, srvkey.exponent + MEGAKI_RSA_EXPBYTES - BN_num_bytes(srv->e));   
  szkr_new_ctx(ctx, ios, srvkey);

  length_t len = 1024;
  byte sdata[1024];
  if (szkr_do_handshake(ctx) == 0) {
    printf("success!\n");
    char msg[] = "hello world!", dummy[ 100 ];
    szkr_send_message(ctx, stuff, 64, NULL, NULL);
    szkr_get_session_data(ctx, sdata, &len);

    sleep(2);
    printf("on to step 2\n");
    close(sfd);
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
      printf("could not connect :(");
      return(0);
    }

    szkr_resume_session(ctx, sdata);
    while(1){sleep(10);}
  }

  freeaddrinfo(result);
  return(0);
}
