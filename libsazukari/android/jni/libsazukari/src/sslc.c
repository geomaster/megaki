#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <errno.h>

#include <openssl/ssl.h>

pthread_mutex_t *lock_cs;
long *lock_count;

pthread_mutex_t locker = PTHREAD_MUTEX_INITIALIZER;
int mtctr;

unsigned long id_function(void)
{
	return ((unsigned long) pthread_self());
}

void locking_function(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&lock_cs[type]);
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&lock_cs[type]);
	}
}

void ssl_thread_setup(void)
{
	int num = CRYPTO_num_locks();
	int ctr;

	lock_cs = (pthread_mutex_t*) OPENSSL_malloc(num * sizeof(pthread_mutex_t));
	lock_count = (long*) OPENSSL_malloc(num * sizeof(long));

	for (ctr = 0; ctr < num; ctr++) {
		lock_count[ctr] = 0;
		pthread_mutex_init(&lock_cs[ctr], NULL);
	}

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
}


void ssl_thread_cleanup(void)
{
	int ctr;

	CRYPTO_set_locking_callback(NULL);

	for (ctr = 0; ctr < CRYPTO_num_locks(); ctr++) {
		pthread_mutex_destroy(&lock_cs[ctr]);
	}

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}
