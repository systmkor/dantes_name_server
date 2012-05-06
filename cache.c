#include <time.h>
#include <limits.h>
#include "extypes.h"
#include "smartalloc.h"
#include "cache.h"
#include "dns.h"


extern ht_entry *cache;


void add_record(hash_key cache_key, rr_t rr) {
  ht_entry *cache_entry;
  record_t *curr_record;
  record_t *new_record;
  bool record_exists = RECORD_DNE;
  
  cache_entry = find_entry(cache_key);

  if (cache_entry == NULL) {
    add_entry(cache_key);
    cache_entry = find_entry(cache_key);
  }
 
  if (cache_entry->record == NULL)
    cache_entry->record = record_alloc();

  curr_record = cache_entry->record;
  
  do {
    if (rr_cmp(curr_record->rr, rr))
      record_exists = RECORD_EXISTS;

    else 
      curr_record = curr_record->next;
  }while (curr_record->next != NULL && record_exists == RECORD_DNE);

  if (!record_exists) {
    new_record = record_alloc();
    curr_record->next = new_record;
    new_record->prev = curr_record;
    new_record->rr = rr;
    time(&(new_record->time_created));
  }
}

record_t *record_alloc(void) {
   record_t *record = (record_t *)malloc(sizeof(record_t));
   record->next = NULL;
   record->prev = NULL;
   return record;
}

void add_entry(hash_key cache_key) {
  ht_entry *cache_entry = (ht_entry *)malloc(sizeof(ht_entry));
  cache_entry->key = cache_key;
  cache_entry->record = NULL;
  HASH_ADD_INT(cache, key, cache_entry);
}

ht_entry *find_entry(hash_key cache_key) {
  ht_entry *cache_entry;
  /* return null and remove cache entry if ttl expires*/
  HASH_FIND_INT(cache, &cache_key, cache_entry);
  return cache_entry;
}

void load_root_servers(void) {
  load_root_ns();
  load_root_a();
}

void load_root_a(void) {
  hash_key cache_key;
  rr_t rr;
  uint8_t a_name[20] = {0x01, 'a', 
			0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's',
			0x03, 'n', 'e', 't', '\0'};

  cache_key.name[0] = '.';
  cache_key.name[1] = '\0';
  memcpy(cache_key.name, a_name, 20);

  memcpy(rr.name, a_name, 20);
  rr.type = RR_TYPE_A;
  rr.type = RR_CLASS_IN;
  rr.rdata = a_rdata_alloc();
  (*(a_rdata *)rr.rdata).address = htonl(0xC6290004); //"198.41.0.4"
  add_record(cache_key, rr);
}

void load_root_ns(void) {
  //  static ht_entry cache_entry;
  hash_key cache_key;
  rr_t rr;

  uint8_t a_ns[20] = {0x01, 'a', 
			0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's',
			0x03, 'n', 'e', 't', '\0'};
  /* uint8_t b_ns[20] = {0x01, 'a',  */
  /* 			0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', */
  /* 			0x03, 'n', 'e', 't', '\0'}; */
  /* uint8_t c_ns[20] = {0x01, 'a',  */
  /* 			0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', */
  /* 			0x03, 'n', 'e', 't', '\0'}; */
  /* uint8_t d_ns[20] = {0x01, 'a',  */
  /* 			0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', */
  /* 			0x03, 'n', 'e', 't', '\0'}; */

  cache_key.name[0] = '.';
  cache_key.name[1] = '\0';

  rr.name[0] = '\0';
  rr.type = RR_TYPE_NS;
  rr.type = RR_CLASS_IN;
  rr.ttl = UINT_MAX;
  rr.rdata = malloc(20);
  memcpy(rr.rdata, a_ns, 20);

  add_record(cache_key, rr);
}

a_rdata *a_rdata_alloc(void) {
  a_rdata *a = (a_rdata*)malloc(sizeof(a_rdata));
  bzero(a, sizeof(a_rdata));
  return a;
}


hash_key key_generate(char *name) {
  static hash_key key;
  bzero(key.name, DNS_NAME_MAX_LEN);
  strncpy((char *)key.name, name, DNS_NAME_MAX_LEN);
  return key;
}
