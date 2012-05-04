#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <arpa/inet.h>
#include "smartalloc.h"
#include "dns.h"
#include "cache.h"

ht_entry *cache = NULL;

void process_pkts(conn *Conn) {
  static dns_state *Dstates[USHRT_MAX];
  int listen = LISTEN_TRUE;
  pkt *RecvPkt = pkt_alloc(DATAGRAM_MAX_SIZE);
  int i;
  for (i = 0; i < USHRT_MAX; i += 1)
    Dstates[i] = NULL;

  load_root_servers();

  while (listen) {
    recv_pkt(Conn, RecvPkt);
    process_dns(Dstates, Conn, RecvPkt);
  }
}

void process_dns(dns_state *Dstates[], conn *Conn, pkt *InitPkt) {
  dns_state *Dstate;
  dns_state **temp;

  temp = get_dns_state(Dstates, InitPkt);
  init_dns_state(temp, Conn, InitPkt);
  Dstate = *temp;

  while (Dstate->state != S_LISTEN) {
    switch (Dstate->state) {
      
    case S_RECV_QUERY:
      recv_query(Dstate);
      break;
      
    case S_RECV_RESP:
      printf("Received Responce\n");
      break;
      
    case S_CACHE_CHECK:
      cache_check(Dstate);
      break;

    case S_QUESTIONS_CHECK:
      break;
      
    case S_STORE_IN_CACHE:
      break;
      
    case S_SEND_QUERY:
      break;
      
    case S_SEND_RESP:
      break;
      
    case S_EXIT:
      Dstate->state = S_LISTEN;
      break;
      
    default:
      fprintf(stderr, "!!Unknown STATE!!\n");
      break;
    }
  }
}

void recv_query(dns_state *Dstate) {
  parse_dns_hdr(Dstate);
  parse_question(Dstate);
  print_name(Dstate->external_q.name);
  Dstate->state = S_QUESTIONS_CHECK;
  //  Dstate->state = S_LISTEN;
}

void cache_check(dns_state *Dstate) {

  //create pointer at beginning of q_name_str
  //create pointer at end of q_name_str (put on the null char)
  //end_ptr +1 then keep scanning until ptr+1 =  to the the next
  //lo.edu.

  printf("Cache Check\n");
  Dstate->state = S_LISTEN;
}

void print_name(name_t *name) {
  if (name == NULL)
    return;

  do {
    printf("%s.", name->label);
    name = name->next_label;
  }while(name != NULL);
  printf("\n");
}

void name_to_str(name_t *name, char *namestr) {
  int num_chars = 0;
  if (name == NULL)
    return;

  do {
    num_chars = snprintf(namestr, DNS_LABEL_MAX_LEN, "%s.",  name->label);
    namestr += num_chars; //!!CHECK TO MAK SURE NOT GOING BEYOND BOUNDARIES
    name = name->next_label;
  }while(name != NULL);
  namestr[num_chars] = '\0';
}

void parse_question(dns_state *Dstate) {
  uint8_t *buff;
  uint32_t i;
  printf("parsing question\n");
  buff = Dstate->recvpkt.datagram + DNS_HDR_SIZE;
  copy_name(&(Dstate->recvpkt), buff, &(Dstate->external_q.name));
  name_to_str(Dstate->external_q.name, Dstate->external_q.namestr);
  buff = Dstate->recvpkt.datagram + DNS_HDR_SIZE;
  for (i = 0; i < DNS_NAME_MAX_LEN; i++)
    if (buff[i] == '\0' || DNS_LABEL_PTR(buff[i]))
      break;
  buff += 1;
  Dstate->external_q.qtype = buff[i];//get qtype
  buff += 1;
  Dstate->external_q.qclass = buff[i];  //get qclass
  printf("qtype: %u  :: qclass: %u\n", Dstate->external_q.qtype, Dstate->external_q.qclass);
}

void parse_dns_hdr(dns_state *Dstate) {
  static dns_hdr hdr;
  memcpy(&hdr, &(Dstate->recvpkt.datagram), sizeof(dns_hdr));
  Dstate->id = htons(hdr.id);
  Dstate->rd = DNS_HDR_RD(hdr.code_a);
  Dstate->aa = DNS_HDR_AA(hdr.code_a);
  Dstate->tc = DNS_HDR_TC(hdr.code_a);
  Dstate->qr = DNS_HDR_QR(hdr.code_a);
  Dstate->qdcount = htons(hdr.qdcount);
  Dstate->ancount = htons(hdr.ancount);
  Dstate->nscount = htons(hdr.nscount);
  Dstate->arcount = htons(hdr.arcount);
}

dns_state *add_dns_state(void) {
  dns_state *state = (dns_state *)malloc(sizeof(dns_state));
  state->internal_q.name_answered = 0;
  state->internal_q.type_answered = 0;
  state->external_q.name_answered = 0;
  state->external_q.type_answered = 0;
  return state;
}

void init_dns_state(dns_state **Dstate, conn *Conn, pkt *Pkt) {
  if (*Dstate == NULL) {
    printf("Dstate is NULL\n");
    *Dstate = add_dns_state();
  }

  (*Dstate)->conn = *Conn;
  (*Dstate)->recvpkt = *Pkt;
  (*Dstate)->state = query_or_resp(*Dstate);
  (*Dstate)->external_q.name = NULL;
  (*Dstate)->internal_q.name = NULL;
  bzero((*Dstate)->external_q.namestr, DNS_NAME_MAX_LEN);
  bzero((*Dstate)->internal_q.namestr, DNS_NAME_MAX_LEN);
}

m_state query_or_resp(dns_state *Dstate) {
  uint8_t qr_field = Dstate->recvpkt.datagram[DNS_HDR_QR_OFFSET];
  if(DNS_HDR_QR(qr_field) == QR_QUERY)
    return S_RECV_QUERY;

  return S_RECV_RESP;
}

dns_state **get_dns_state(dns_state *Dstates[], pkt *Pkt) {
  uint16_t id;
  memcpy(&id, Pkt->datagram + DNS_HDR_ID_OFFSET, sizeof(uint16_t));
  id = ntohs(id);
  return Dstates + id;
}



int copy_name(pkt *Pkt, uint8_t *buff, name_t **name) {
  static name_meta_t name_meta;
  //  static name_t *name;
  static name_t *name_temp;

  printf("copying name\n");

  clean_name_meta(&name_meta);

  if (Pkt == NULL || buff == NULL)
    return 0;

  if (*name == NULL)
    *name = name_alloc();

  name_temp = *name;

  while (1) {

    if(handle_pointing(Pkt, buff) == PTR_ERR)
      return GETNAME_ERR;

    name_meta.label_len = (uint16_t)DNS_LABEL_LEN(*buff);
    buff += 1;    
    if (copy_label(&name_meta, &name_temp, buff, Pkt->datagram + Pkt->datagram_len) == END_OF_NAME_TRUE)
      return GETNAME_SUCCESS;

    if ((*name)->next_label == NULL)
      (*name)->next_label = name_alloc();

    (*name)->next_label->prev_label = name_temp;
    name_temp = (*name)->next_label;
    buff += name_meta.chars_read_name;//LABEL_START_OF_STRING(buff);
  }

}

int copy_label(name_meta_t *name_meta, name_t **name, uint8_t *src, uint8_t *src_end) {
  uint16_t i;
  for(i = 0; i < name_meta->label_len && src + i <= src_end; i += 1) {
    (*name)->label[i] = src[i];
    name_meta->chars_read_name +=1;
  }
  //propably have an error condition for going outside of dns packet
  //propably have an error condition for going beyond max name size
  if (src[i] == '\0')
    return END_OF_NAME_TRUE;
  
  return END_OF_NAME_FALSE;
}

void clean_name_meta(name_meta_t *name_meta) {
  if (name_meta == NULL) {
    fprintf(stderr, "clean_name_meta err\n");
    return;
  }

  name_meta->name_len = 0;
  name_meta->label_len = 0;
  name_meta->chars_read_name = 0;
}


name_t *name_alloc(void) {
  name_t *name = (name_t *) malloc(sizeof(name_t));
  bzero(name->label, DNS_LABEL_MAX_LEN);
  name->next_label = NULL;
  name->prev_label = NULL;

  return name;
}

int handle_pointing(pkt *Pkt, uint8_t *buff) {
  static uint32_t ptr;
  ptr = 0;

  if (buff == NULL) {
    fprintf(stderr, "handl_pointing -- buff NULL\n");
    return PTR_ERR;
  }

  if (DNS_LABEL_PTR(*buff)) {
    ptr = (uint32_t)DNS_LABEL_PTR_VALUE(*buff);

    if (ptr <= Pkt->datagram_len) {
      buff = Pkt->datagram + ptr;
      return PTR_SUCCESS;
    }
    
    else {
      fprintf(stderr, "PTR IS MESSED UP :: PACKET IS BROKE\n");
      return PTR_ERR;
    }
  }
  return PTR_SUCCESS;
}


