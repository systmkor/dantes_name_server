#ifndef DNS_H_
#define DNS_H_

#include <stdint.h>

#define RR_TYPE_A (1)
#define RR_TYPE_NS (2)
#define RR_TYPE_CNAME (5)
#define RR_TYPE_SOA (6)
#define RR_TYPE_PTR (12)
#define RR_TYPE_ALL (255)
#define RR_TYPE_AAAA (0x001C)

#define RR_CLASS_IN (1)

#define QR_QUERY (0)
#define QR_RESP (1)

#define DNS_UDP_MTU (512) //bytes

#define DNS_HDR_QR_OFFSET (2) //bytes
#define DNS_HDR_ID_OFFSET (0)

#define DNS_HDR_ID(addr) (*(uint16_t *)addr)
#define DNS_HDR_QR(byte) ((DNS_HDR_QR_MASK & (uint8_t)byte))
#define DNS_HDR_OPCODE(byte) ((DNS_HDR_OPCODE_MASK & (uint8_t)byte) >> 3)
#define DNS_HDR_AA(byte) ((DNS_HDR_AA_MASK & (uint8_t)byte))
#define DNS_HDR_TC(byte) ((DNS_HDR_TC_MASK & (uint8_t)byte))
#define DNS_HDR_RD(byte) ((DNS_HDR_RD_MASK & (uint8_t)byte))
#define DNS_HDR_RA(byte) ((DNS_HDR_RA_MASK & (uint8_t)byte))
#define DNS_HDR_RCODE(byte) (DNS_HDR_RCODE_MASK & (uint8_t)(byte))
#define DNS_HDR_SIZE (12) //bytes


#define DNS_HDR_QR_MASK (0x80)
#define DNS_HDR_OPCODE_MASK (0x78)
#define DNS_HDR_AA_MASK (0x04)
#define DNS_HDR_TC_MASK (0x02)
#define DNS_HDR_RD_MASK (0x01)
#define DNS_HDR_RA_MASK (0x80)
#define DNS_HDR_RCODE_MASK (0x0F)

#define LISTEN_TRUE (1)
#define LISTEN_FALSE (0)

#define DNS_LABEL_MAX_LEN (63) //bytes
#define DNS_NAME_MAX_LEN (255) //bytes
#define QNAME_LEN (DNS_NAME_MAX_LEN);
#define RR_NAME_LEN (DNS_NAME_MAX_LEN)
#define DNS_LABEL_PTR_MASK (0xC0)
#define DNS_LABEL_PTR(byte) (DNS_LABEL_PTR_MASK == (DNS_LABEL_PTR_MASK & byte))
#define DNS_LABEL_PTR_VALUE(byte) (DNS_LABEL_PTR_MASK & byte)
#define DNS_LABEL_LEN_MASK (0x3F)
#define DNS_LABEL_LEN(byte) (DNS_LABEL_LEN_MASK & byte)

#define QUEST_ANSW (1)
#define QUEST_NOT_ANSW (0)

#define RECURSE_YES (1)
#define RECURSE_NO (0)



#include "conn.h"

enum M_STATE {
  S_START, S_FINISH, S_EXIT, S_DONE, S_PAUSE,
  S_LISTEN,
  S_RECV_QUERY, S_RECV_RESP, S_SEND_QUERY, S_SEND_RESP,
  S_HDR_QUEST, S_HDR_ANSW, S_HDR_AUTH, S_HDR_ADDI,
  S_STORE_IN_CACHE,
  S_CACHE_CHECK,
  S_EXTERN_QUEST, S_EXTERN_ANSW,
  S_INTERN_QUEST, S_INTERN_ANSW
};
typedef enum M_STATE m_state;

typedef uint8_t bool;
typedef uint16_t dns_id;

struct name_s {
  uint8_t label[DNS_LABEL_MAX_LEN];
  struct name_s *next_label;
  struct name_s *prev_label;
};
typedef struct name_s name_t;
  

struct q_rdata_s {
  name_t *name;
  uint16_t qtype;
  uint16_t qclass;
};
typedef struct q_rdata_s q_rdata;

struct dns_q_s {
  bool name_answered;
  bool type_answered;
  //  q_rdata question;
  name_t *name;
  char namestr[DNS_NAME_MAX_LEN];
  uint16_t qtype;
  uint16_t qclass;
};
typedef struct dns_q_s dns_q;

struct dns_state_s {
  m_state state;
  conn conn;
  pkt recvpkt;
  pkt sendpkt;

  dns_q internal_q;
  dns_q external_q;

  dns_id id;
  bool rd;
  bool aa;
  bool tc;
  bool qr;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};
typedef struct dns_state_s dns_state;


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

struct name_meta_s {
  uint16_t name_len;
  uint16_t label_len;
  uint16_t chars_read_name;
};
typedef struct name_meta_s name_meta_t;

#define LABEL_COPY_ERR (-1)
#define PTR_ERR (0)
#define PTR_SUCCESS (1)
#define GETNAME_ERR (0)
#define GETNAME_SUCCESS (1)
#define END_OF_NAME_TRUE (1)
#define END_OF_NAME_FALSE (0)
#define LABEL_START_OF_STRING(addr) (addr += 1)

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



void process_pkts(conn *Conn);
void process_dns(dns_state *Dstates[], conn *Conn, pkt *InitPkt);
dns_state *add_dns_state(void);
void init_dns_state(dns_state **Dstate, conn *Conn, pkt *Pkt);
m_state query_or_resp(dns_state *Dstate);
dns_state **get_dns_state(dns_state *Dstates[], pkt *Pkt);  
name_t *name_alloc(void);
void clean_name_meta(name_meta_t *name_meta);
int handle_pointing(pkt *Pkt, uint8_t *buff);

void parse_dns_hdr(dns_state *Dstate);
void parse_question(dns_state *Dstate);
void print_name(name_t *name);
void name_to_str(name_t *name, char *namestr);
void recv_query(dns_state *Dstate);
int copy_name(pkt *Pkt, uint8_t *buff, name_t **name);
int copy_label(name_meta_t *name_meta, name_t **name, uint8_t *src, uint8_t *src_end);
void cache_check(dns_state *Dstate);
#endif
