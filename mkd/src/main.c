#include <stdio.h>
#include "yugi.h"
#include "yami.h"
#include <unistd.h>
#include "pegasus.h"
#include <malloc.h>
#include <signal.h>
#include "pmdk.h"
yugi_t* yugi;

void handle_signal(int sig)
{
  yugi_stop(yugi);
}

int writecb(byte* buf, length_t len, void* pam)
{
  printf("What are you doing honey...? I'm not ready y-y-yet... Yamette kure!\n");
  return 0;
}
#include <assert.h>

int broker(void* param)
{
  fprintf(stderr, "Err... I'm the broker... Or something... This is embarrassing.\n");
  fflush(stderr);
  while (1)  {
    pegasus_resp_hdr_t resp;
    pegasus_req_hdr_t req;
    pegasus_start_req_t sreq;
    assert(read(STDIN_FILENO, &req, sizeof(pegasus_req_hdr_t)) == sizeof(pegasus_req_hdr_t));
    int st=sizeof(pegasus_quit_req_t);
 if(req.type==PEGASUS_REQ_START) {   byte dump[1000];
   assert(read(STDIN_FILENO,dump,4)==4);st=sizeof(pegasus_start_req_t);}
    assert(read(STDIN_FILENO, &sreq, st) == st);if(req.type==PEGASUS_REQ_START)fprintf(stderr, "Broker starts!\n");
    else fprintf(stderr, "Broker quits!\n");
    resp.type =(req.type==PEGASUS_REQ_START? PEGASUS_RESP_START_OK : PEGASUS_RESP_QUIT_OK);
    assert(write(STDOUT_FILENO, &resp, sizeof(pegasus_resp_hdr_t)) == sizeof(pegasus_resp_hdr_t));
  }
}

byte cert[1766];
int main(int argc, char** argv)
{
  yugi = malloc(yugi_getcontextsize());
  
  FILE * f = fopen("server-private.pem", "r");
  fread(cert, 1766, 1, f);
  fclose(f);
  
  pegasus_conf_t pconf = {
    .write_cb = &writecb,
    .start_broker_cb = &broker,
    .start_broker_cb_param = NULL,
    .context_data_length = 4,
    .minion_pool_size = 25,
    .log_level = LOG_DEBUG2,
    .log_file = stderr,
    .lock_timeout = 10,
    .message_timeout = { .tv_sec = 1, .tv_usec = 0 }
  };
  if (pegasus_init(&pconf) != 0) {
    fprintf(stderr, "Pegasus did not start up\n");
    return -1;
  }

  yami_conf_t yconf = {
    .certificate_passphrase = "crno je sve",
    .certificate_buffer = cert,
    .certificate_size = 1766
  };
  if (yami_init(&yconf) != 0) {
    fprintf(stderr, "Yami did not start up\n");
    return -1;
  }
  struct sigaction siginth;  
  siginth.sa_handler = handle_signal;
  sigemptyset(&siginth.sa_mask);
  siginth.sa_flags = 0;
  sigaction(SIGINT, &siginth, NULL);

  yugi_conf_t conf = {
    .listen_address = "127.0.0.1",
    .listen_port = 6363,
    .thread_count = 2,
    .queue_size = 2000,
    .log_file = stderr,
    .log_level = LOG_DEBUG2,
    .receive_timeout = 6000,
    .buffer_length = 16384,
    .socket_backlog = 50,
    .watchdog_interval = 5000,
    .lock_timeout = 40
  };
  yugi_init(yugi, &conf);
  yugi_start(yugi);
  yugi_cleanup(yugi);
  yami_destroy();
  pegasus_cleanup();

  free(yugi);
  return(0);
}
