/*************************************************************************/
/* sslc.c 				 */
/*  v. 0.1 								 */
/*  Copyright (C) 2008 Paolo Ardoino,                   		 */
/*  by Paolo Ardoino  < paolo.ardoino@gmail.com > 			 */
/*                                                                       */
/* This program is free software; you can redistribute it and/or 	 */
/* modify it under the terms of the GNU General Public License as 	 */
/* published by the Free Software Foundation; either version 2 of the 	 */
/* License, or (at your option) any later version.			 */
/* 									 */
/* This program is distributed in the hope that it will be useful, but 	 */
/* WITHOUT ANY WARRANTY; without even the implied warranty of 		 */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 	 */
/* General Public License for more details.				 */
/*  									 */
/* You should have received a copy of the GNU General Public License 	 */
/* along with this program; if not, write to the Free Software 		 */
/* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-	 */
/* 1307, USA.								 */
/*************************************************************************/

#ifndef SSLC_H
#define SSLC_H
#include <netdb.h>

#define MAX_THREADS 768
#define BUFFER_SIZE 512

#define READ_BUFFER(ssl, buf) do { SSL_read((SSL *) ssl, (buf), BUFFER_SIZE); (buf)[strlen(buf) - 2] = '\0'; } while(0)
#define WRITE_BUFFER(ssl, buf) do { SSL_write((SSL *) ssl, (buf), strlen(buf)); } while(0)

void ssl_thread_setup(void);
void ssl_thread_cleanup(void);
void locking_function(int mode, int type, const char *file, int line);
unsigned long id_function(void);

#endif /* SSLC_H */
