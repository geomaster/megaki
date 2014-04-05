#include <stdio.h>
#include "yugi.h"
#include "yami.h"
#include <malloc.h>
#include <signal.h>
yugi_t* yugi;

void handle_signal(int sig)
{
  yugi_stop(yugi);
}

byte cert[1766];
int main(int argc, char** argv)
{
  yugi = malloc(yugi_getcontextsize());
  
  FILE * f = fopen("server-private.pem", "r");
  fread(cert, 1766, 1, f);
  fclose(f);
  
  yami_conf_t yconf = {
    .certificate_passphrase = "crno je sve",
    .certificate_buffer = cert,
    .certificate_size = 1766
  };
  if (yami_init(&yconf) != 0)
    fprintf(stderr, "Yami did not start up\n");
  
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
    .watchdog_interval = 5000
  };
  yugi_init(yugi, &conf);
  yugi_start(yugi);
  yugi_cleanup(yugi);
  yami_destroy();
  free(yugi);
  return(0);
}
