#ifndef DNS_H_
#define DNS_H_

#include <stdint.h>
#include "extypes.h"
#include "dns_types.h"
#include "cache.h"
#include "conn.h"

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
#define DNS_HDR_QR(byte) ((DNS_HDR_QR_MASK & (uint8_t)byte) >> 7) //potential issues
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

enum M_STATE {
  S_START, S_FINISH, S_EXIT, S_DONE, S_PAUSE,
  S_LISTEN,
  S_RECV_QUERY, S_RECV_RESP, S_SEND_QUERY, S_SEND_RESP,
  S_HDR_QUEST, S_HDR_ANSW, S_HDR_AUTH, S_HDR_ADDI,
  S_STORE_IN_CACHE,
  S_CACHE_CHECK,
  S_RESOLVE, S_QUESTIONS_CHECK,
  S_CREATE_RESP, S_CREATE_QUERY,
  S_EXTERN_QUEST, S_EXTERN_ANSW,
  S_INTERN_QUEST, S_INTERN_ANSW
};
typedef enum M_STATE m_state;


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
  bool question_asked;
  bool name_answered;
  bool type_answered;
  name_t *name_pos; //where in the name you are currently are at to check cache
  q_rdata question;
  name_t *name;
  //hash_key key;
  char namestr[DNS_NAME_MAX_LEN];
  uint16_t qtype;
  uint16_t qclass;
};
typedef struct dns_q_s dns_q;

struct rr_l_s {
  rr_t rr;
  struct rr_l_s *next;
  struct rr_l_s *prev;
};
typedef struct rr_l_s rr_l;

struct dns_state_s {
  m_state state;
  conn conn;
  pkt recvpkt;
  pkt sendpkt;
  // turn internal_q etc into a linked list of qs and only add to the list when a quesiton is
  // answered
  hash_key question_key;
  ht_entry *cache_ret;  
  rr_l *reply_rr;

  dns_q internal_q;
  dns_q external_q;
  dns_q *q;

  dns_id id; //identification value
  bool rd; //recurse or not
  bool aa; //authorative answer
  bool tc; //truncate
  bool qr; //question or response
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};
typedef struct dns_state_s dns_state;


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
void store_in_cache(dns_state *Dstate);
void resolve(dns_state *Dstate);
name_t *end_of_name(name_t *name);
bool rr_cmp(rr_t a, rr_t b);
#endif
