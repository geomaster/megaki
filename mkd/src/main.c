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
  signal(SIGINT, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
  
  byte* ppp = NULL;

  fprintf(stderr, "Broker starts\n");
  fflush(stderr);
  while (1)  {
    pegasus_req_hdr_t req;
    if (read(STDIN_FILENO, &req, sizeof(pegasus_req_hdr_t)) != sizeof(pegasus_req_hdr_t))
      goto die;

    pegasus_resp_hdr_t rsphdr;
    rsphdr.type = 0xFF;
    if (req.type == PEGASUS_REQ_START) {
      pegasus_start_req_t streq;
      if (read(STDIN_FILENO, &streq, sizeof(pegasus_start_req_t)) != sizeof(pegasus_start_req_t))
        goto die;

      byte platipus[2000];
      assert(streq.datasize < 2000);
      if (read(STDIN_FILENO, platipus, streq.datasize) != streq.datasize)
        goto die;

      fprintf(stderr, "Broker allocated for job!\n");
      rsphdr.type = PEGASUS_RESP_START_OK;
    } else if (req.type == PEGASUS_REQ_QUIT) {
      pegasus_quit_req_t qreq;
      if (read(STDIN_FILENO, &qreq, sizeof(pegasus_quit_req_t)) != sizeof(pegasus_quit_req_t))
        goto die;

      fprintf(stderr, "Broker decommissioned for the job\n");
      rsphdr.type = PEGASUS_RESP_QUIT_OK;

    } else if (req.type == PEGASUS_REQ_HANDLE) {
      pegasus_handle_req_t hreq;
      if (read(STDIN_FILENO, &hreq, sizeof(pegasus_handle_req_t)) != sizeof(pegasus_handle_req_t))
        goto die;

      rsphdr.type = PEGASUS_RESP_HANDLE_OK;
      ppp = malloc(256*1024);
      assert(hreq.msgsize < 256*1024);
      if (read(STDIN_FILENO, ppp, hreq.msgsize) != hreq.msgsize)
        goto die;

      fprintf(stderr, "Broker handling message (%d): ", (int) hreq.msgsize);
      fwrite(ppp, hreq.msgsize, 1, stderr);
      fprintf(stderr, "\n");

      free(ppp);
      ppp = NULL;
    }
    write(STDOUT_FILENO, &rsphdr, sizeof(pegasus_resp_hdr_t));
    if (rsphdr.type == PEGASUS_RESP_HANDLE_OK) {

      pegasus_handle_resp_t hresp;
      char response[] = "Broker says: hello!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      hresp.respsize = sizeof(response) - 1;
      write(STDOUT_FILENO, &hresp, sizeof(hresp));
      write(STDOUT_FILENO, response, sizeof(response) - 1);
    }
  }

die:
  fprintf(stderr, "Broker dead for some reason");
  if (ppp)
    free(ppp);
  fflush(stderr);
  return( 0 );
}

byte cert[1766];
int main(int argc, char** argv)
{
  yugi = malloc(yugi_getcontextsize());
  
  FILE * f = fopen("server-private.pem", "r");
  fread(cert, 1766, 1, f);
  fclose(f);
  signal(SIGPIPE, SIG_IGN);
  
  pegasus_conf_t pconf = {
    .start_broker_cb = &broker,
    .start_broker_cb_param = NULL,
    .context_data_length = sizeof(pegasus_yami_payload_t),
    .minion_pool_size = 4,
    .log_level = LOG_DEBUG2,
    .log_file = stderr,
    .lock_timeout = 10,
    .buffer_sentinel = 17,
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
    .receive_timeout = 60000,
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
