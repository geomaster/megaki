#include "arcangelo.h"
#include <unistd.h>

int arcangelo_start_broker(void* param)
{
  arcangelo_config_t* config = (arcangelo_config_t*) param;
  /* TODO: setuid() and setgid() */

  char* const argv[] = {
    config->shell, /* first argument: command name */
    "-c", /* standard -c to run a command specified by arg */
    config->command, /* command to run */
    NULL /* terminator */
  };

  execv(config->shell, argv);
  return( -1 );
}

