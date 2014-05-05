#include "tokenbank.h"
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <malloc.h>
#include <time.h>
/* Proof of concept fast in-memory token bank. Future implementations
 * should be writing to disk. There is no need to keep this in-memory
 * when we're network-bound, it's just silly. */
 
typedef uint16_t token_idx; /* change to uint32_t for more than 65535 tokens! */
typedef uint32_t token_timestamp;

unsigned int maxtokens, maxbuckets;
pthread_mutex_t tokmut;

typedef struct tokintentry {
  tokentry entry;
  token_idx heapidx;
  token_timestamp time;
} tokintentry;

typedef struct tokenbucket {
  token_idx i;
  struct tokenbucket* next;
  int collisions;
} tokenbucket;


tokintentry* tokenlist;
tokenbucket** tokenhashmap;

/* remove from heap, do not touch tokencount, remove from
 * hashmap, return bucket for future use */
token_idx popmin(tokenbucket**);
token_timestamp gettimestamp();
tokenbucket* find(byte* token, tokenbucket** prev);
void heapifyup(token_idx);
void heapifydown(token_idx);
token_idx hash(byte*);
tokenbucket* findh(byte* token, token_idx h, tokenbucket** prev);
void heapswap(token_idx hi1, token_idx hi2);

typedef unsigned int uint;

/* min-heap of timestamps */
token_idx* tokenheap;
uint tokencount;

#define FNV_OFFSET          2166136261U
#define FNV_PRIME           16777619U

#define HEAP_ROOT           1
#define HEAP_LCHILD(a)      (2*(a))
#define HEAP_RCHILD(a)      (2*(a)+1)
#define HEAP_PARENT(a)      ((a)/2)

token_idx popmin(tokenbucket** lastbucket)
{
  token_idx minid = tokenheap[HEAP_ROOT];
  heapswap(HEAP_ROOT, tokencount + HEAP_ROOT - 1);
  
  --tokencount;
  heapifydown(HEAP_ROOT);
  ++tokencount;
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  token_idx h = hash(tokenlist[minid].entry.token);
  tokenbucket *pp, *pb = findh(tokenlist[minid].entry.token, h, &pp);
  if (pp)
    pp->next = pb->next;
  else
    tokenhashmap[h] = pb->next;
  
  *lastbucket = pb;
  return minid;
}

token_timestamp gettimestamp()
{
  return((token_timestamp)clock());
}

tokenbucket* find(byte* token, tokenbucket** prev)
{
  return(findh(token, hash(token), prev));
}

tokenbucket* findh(byte* token, token_idx h, tokenbucket** prev)
{
  tokenbucket *f, *p;
  p = NULL;
  f = tokenhashmap[h];
  while (f && (memcmp(token, tokenlist[f->i].entry.token, MEGAKI_TOKEN_BYTES) != 0)) {
    p = f;
    f = f->next;
  }
  if (prev) *prev = p;
  return(f); 
}

void heapifyup(token_idx hi)
{
  while (HEAP_PARENT(hi) >= HEAP_ROOT && tokenlist[tokenheap[HEAP_PARENT(hi)]].time > tokenlist[tokenheap[hi]].time) {
    heapswap(hi, HEAP_PARENT(hi));
    hi = HEAP_PARENT(hi);
  }
}

void heapifydown(token_idx hi)
{
  /* hope to god compiler optimizes this */
  while (((HEAP_LCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_LCHILD(hi)]].time) ||
    (HEAP_RCHILD(hi) <= tokencount && tokenlist[tokenheap[hi]].time > tokenlist[tokenheap[HEAP_RCHILD(hi)]].time))) {
    if (tokenlist[tokenheap[HEAP_LCHILD(hi)]].time < tokenlist[tokenheap[HEAP_RCHILD(hi)]].time) {
      heapswap(hi, HEAP_LCHILD(hi));
      hi = HEAP_LCHILD(hi);
    } else {
      heapswap(hi, HEAP_RCHILD(hi));
      hi = HEAP_RCHILD(hi);
    }
  }
}

void heapswap(token_idx hi1, token_idx hi2)
{
  tokintentry* t1 = &tokenlist[tokenheap[hi1]], *t2 = &tokenlist[tokenheap[hi2]];
  t1->heapidx = hi2; t2->heapidx = hi1;
  token_idx t = tokenheap[hi1];
  tokenheap[hi1] = tokenheap[hi2];
  tokenheap[hi2] = t;
}

token_idx hash(byte* token)
{
  uint32_t hash = FNV_OFFSET;
  int i;
  for (i = 0; i < MEGAKI_TOKEN_BYTES; ++i) {
    hash ^= token[i];
    hash *= FNV_PRIME;
  }
  return hash % maxbuckets;
}

int tokinit(unsigned int maxtoks, unsigned int maxbucks)
{
  tokenlist = (tokintentry*)malloc(maxtoks * sizeof(tokintentry));
  if (tokenlist == NULL)
    return(0);
    
  tokenhashmap = (tokenbucket**)malloc(maxbucks * sizeof(tokenbucket*));
  if (tokenhashmap == NULL)
    return(0);
    
  tokenheap = (token_idx*)malloc((2 * maxtoks + 1) * sizeof(token_idx));
  if (tokenheap == NULL)
    return(0);
    
  memset(tokenlist, 0, maxtoks * sizeof(tokintentry));
  memset(tokenhashmap, 0, maxbucks * sizeof(tokenbucket*));
  memset(tokenheap, 0, (2 * maxtoks + 1) * sizeof(token_idx));
  
  pthread_mutex_init(&tokmut, 0);
  maxtokens = maxtoks;
  maxbuckets = maxbucks;
  tokencount = 0;
  return(1);
}

void bucket_sanity(const char* site, int diff)
{
  int seenb = 0, i;
  for (i = 0; i < maxbuckets; ++i) {
    tokenbucket* tb = tokenhashmap[i];
    while (tb) {
      ++seenb;
      tb = tb->next;
    }
  }
  
  if (seenb - tokencount != diff) {
    fprintf(stderr, "I saw %d buckets and there are %d tokens (happened at %s)\n", seenb, tokencount, site);
    raise(SIGINT);
  }
}
tokentry* tok_create(byte* token)
{
  pthread_mutex_lock(&tokmut);
  //if (tokencount>1&&tokenheap[1]==tokenheap[2])raise(SIGINT);
  /*int qq,s0=0;
  for(qq=1;qq<=tokencount;++qq){if(tokenheap[qq]==0){if(s0)raise(SIGINT);s0=1;}}
  */
  token_idx i = tokencount, final = HEAP_ROOT + tokencount - 1;
  //if(token[0]==0xb9)raise(SIGINT);
  tokenbucket* tb = NULL;
  if (tokencount >= maxtokens) {
    i = popmin(&tb);
  } else {
    final = HEAP_ROOT + tokencount;
    ++tokencount;
  }
  
  /* bucket_sanity("after pop", -1); */
  
  tokintentry *e = tokenlist + i;
  e->time = gettimestamp();
  e->heapidx = final;
  memcpy(e->entry.token, token, MEGAKI_TOKEN_BYTES);
  tokenheap[final] = i;
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  heapifyup(final);
  //if (tokencount==100&&tokenheap[1]==tokenheap[100])raise(SIGINT);
  
  token_idx h = hash(token);
  if (!tb)
    tb = (tokenbucket*)malloc(sizeof(tokenbucket));
  tb->collisions = -1;
  tb->i = i;
  tb->next = NULL;
  
  tokenbucket * f = NULL;
  if (!tokenhashmap[h]) {
    tokenhashmap[h] = tb;
  } else {
    f = tokenhashmap[h];
    ++f->collisions;
    while (f->next)
      f = f->next;
    f->next = tb;
  }
  
  /* bucket_sanity("after all", 0); */
  
  pthread_mutex_unlock(&tokmut);
  return(&e->entry);
}

void tok_renew(tokentry* te)
{
  pthread_mutex_lock(&tokmut);
  tokintentry* entry = (tokintentry*)te; 
  entry->time = gettimestamp();
  heapifydown(entry->heapidx);
  pthread_mutex_unlock(&tokmut);
}

tokentry* tok_find(byte* token)
{
  pthread_mutex_lock(&tokmut);
  tokenbucket* tb = find(token, NULL);
  pthread_mutex_unlock(&tokmut);
  if (!tb) {
    return( NULL );
  } else {
    return (tokentry*)&tokenlist[tb->i];
  }
}

void tokshutdown()
{
  token_idx i;
  for (i = 0; i < maxbuckets; ++i) {
    tokenbucket * tb = tokenhashmap[i];
    while (tb) {
      
      tokenbucket* tb2 = tb->next;
      free(tb);
      tb = tb2;
    }
  }
  free(tokenhashmap);
  free(tokenlist);
  free(tokenheap);
}
