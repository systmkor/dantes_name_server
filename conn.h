
#ifndef CONN_H_
#define CONN_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define DEFAULT_PORT (DNS_PORT)
#define DNS_PORT (4000)
#define SOCK_ERR (-1)


#define DOMAIN (AF_INET)
#define TYPE (SOCK_DGRAM)
#define PROTOCOL (0)

#define BIND_SUCCESS (1)
#define BIND_FAILURE (0)
#define BIND_ERR (-1)

#define GETSOCKNAME_ERR (-1)

#define SENDTO_FLAGS (0)
#define SENDTO_ERR (-1)

#define RECVFROM_FLAGS (0)
#define RECVFROM_ERR (-1)

#define DATAGRAM_MAX_SIZE (1500)

struct conn_s {
  int sockfd;
  struct sockaddr_in local;
  struct sockaddr_in remote;
  socklen_t len;
};

typedef struct conn_s conn;

struct pkt_s {
  uint32_t mtu;
  uint8_t datagram[DATAGRAM_MAX_SIZE];
  uint32_t datagram_len;
};

typedef struct pkt_s pkt;


int s_socket(int domain, int type, int protocol);
void s_bind(int sockfd, const struct sockaddr *addr,
	    socklen_t addrlen);
void s_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

conn *listening(void);

void send_pkt(conn *Conn, pkt *Pkt);
void s_sendto(int sockfd, const void *buf, size_t len, int flags,
	      const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t s_recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen);

int select_call(int socket, int seconds, int useconds);
void recv_pkt(conn *Conn, pkt *Pkt);

pkt *pkt_alloc(uint32_t mtu);

#define LISTENING_SUCCESS (1)
#define LISTENING_FAILURE (0)

#endif
