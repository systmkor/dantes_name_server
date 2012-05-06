
#ifndef DNS_TYPES_H_
#define DNS_TYPES_H_

#include <stdint.h>

#define DNS_LABEL_MAX_LEN (63) //bytes
#define DNS_NAME_MAX_LEN (255) //bytes

struct rr_s {
  uint8_t name[DNS_NAME_MAX_LEN];
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
  void *rdata;
};
typedef struct rr_s rr_t;

struct rr_hdr_s {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
}__attribute__((packed));
typedef struct rr_hdr_s rr_hdr_t;

struct ns_rdata_s {
  uint8_t nsdname[DNS_NAME_MAX_LEN];
};
typedef struct ns_rdata_s ns_rdata; 

struct ptr_rdata_s {
  uint8_t ptrdname[DNS_NAME_MAX_LEN];
};
typedef struct ptr_rdata_s ptr_rdata; 

struct a_rdata_s {
  uint32_t address;
};
typedef struct a_rdata_s a_rdata;

struct dns_hdr_s {
  uint16_t id;
  uint8_t code_a; //qr-opcode-aa-tc-rd
  uint8_t code_b; //ra-z-rcode
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
}__attribute__((packed));
typedef struct dns_hdr_s dns_hdr;


#endif
