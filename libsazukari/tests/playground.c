#include <stdio.h>
#include <sazukari.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/pem.h>
typedef struct timespec timespec;

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
timespec diff(timespec end, timespec start)
{
    timespec temp;
      if ((end.tv_nsec-start.tv_nsec)<0) {
            temp.tv_sec = end.tv_sec-start.tv_sec-1;
                temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
                  } else {
                        temp.tv_sec = end.tv_sec-start.tv_sec;
                            temp.tv_nsec = end.tv_nsec-start.tv_nsec;
                              }
        return temp;
}

void report_time(struct timespec td)
{
  printf("time: %ldus\n", (1000000000*td.tv_sec+td.tv_nsec)/1000);
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

  byte *resp;
  struct timespec ts, ts2;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  if (szkr_do_handshake(ctx) == 0) {
    /* printf("success!\n"); */
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    struct timespec td = diff(ts2, ts);
    printf("hs: ");
    report_time(td);
    
    char msg[] = "hello world!", dummy[ 100 ];
    clock_gettime(CLOCK_MONOTONIC, &ts);
    szkr_send_message(ctx, stuff, 64, &resp, &len);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td = diff(ts2, ts);
    printf("msg: ");
    report_time(td);

    printf("response: [");
    fwrite(resp, len, 1, stdout);
    printf("]\n");

    len = 1024;
    szkr_get_session_data(ctx, sdata, &len);

    sleep(2);
    /* printf("on to step 2\n"); */
    close(sfd);
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
      printf("could not connect :(");
      return(0);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    szkr_resume_session(ctx, sdata);
    clock_gettime(CLOCK_MONOTONIC, &ts2);
    td = diff(ts2, ts);
    printf("rehs: ");
    report_time(td);
    memcpy(stuff, "CHAO!", 5);

    szkr_send_message(ctx, stuff, 64, &resp, &len);
    /* printf("here's what i have: "); */
    /* fwrite(resp, len, 1, stdout); */
    /* printf("\n"); */
    printf("response: [");
    fwrite(resp, len, 1, stdout);
    printf("]\n");

    {sleep(10);}
  }

  freeaddrinfo(result);
  return(0);
}
