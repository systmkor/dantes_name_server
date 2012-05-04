
#ifndef CACHE_H_
#define CACHE_H_

#include "dns.h"
#include "uthash.h"


struct hash_key_s {
  uint8_t name[DNS_NAME_MAX_LEN];  
  //  uint16_t type;
};

typedef struct hash_key_s hash_key;

struct record_s {
  rr_t rr;
  time_t time_created;
  struct record_s *next;
  struct record_s *prev;  
};
typedef struct record_s record_t;

struct ht_entry_s { 
  hash_key key;
  record_t *record;
  UT_hash_handle hh;
};
typedef struct ht_entry_s ht_entry;



record_t *record_alloc(void);
void add_record(hash_key cache_key, rr_t rr);
void add_entry(hash_key cache_key);
ht_entry *find_entry(hash_key cache_key);
a_rdata *a_rdata_alloc(void);
void load_root_a(void);
void load_root_ns(void);
void load_root_servers(void);


#endif
