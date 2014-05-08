#ifndef __ARCANGELO_H__
#define __ARCANGELO_H__
#include <stdio.h>

typedef struct arcangelo_config_t {
  /*** Configuration options for Arcangelo ***/

  /*** Shell program to run ***/
  char*           shell;

  /*** Command to run in the shell ***/
  char*           command;

  /*** File to bind standard error output to ***/
  FILE*           stderr_bind;
} arcangelo_config_t;

int arcangelo_start_broker(void* param);

#endif /* __ARCANGELO_H__ */
