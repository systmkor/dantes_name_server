#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/select.h>

#include "conn.h"

conn *listening(void) {
  conn* Conn = (conn *)malloc(sizeof(conn));
  int len = sizeof(Conn->local);

  Conn->sockfd = s_socket(DOMAIN, TYPE, PROTOCOL);

  bzero(&(Conn->local), sizeof(Conn->local));
  Conn->local.sin_family = DOMAIN;
  Conn->local.sin_addr.s_addr = htonl(INADDR_ANY); //??
  Conn->local.sin_port = htons(DEFAULT_PORT);

  s_bind(Conn->sockfd, (struct sockaddr *)&(Conn->local),
         sizeof(Conn->local));
  s_getsockname(Conn->sockfd, (struct sockaddr *)&(Conn->local),
                (socklen_t *)&len);

  Conn->len = sizeof(Conn->remote);

  return Conn;
}

int s_socket(int domain, int type, int protocol) {
  int sockfd = socket(domain, type, protocol);
  if (sockfd == SOCK_ERR) 
    perror("s_socket"), exit(EXIT_FAILURE);

  return sockfd;
}

void s_bind(int sockfd, const struct sockaddr *addr,
	    socklen_t addrlen) {
  int ret_val = bind(sockfd, addr, addrlen);

  if (ret_val == BIND_ERR)
    perror("s_socket"), exit(EXIT_FAILURE);

}

void s_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  int ret_val =  getsockname(sockfd, addr, addrlen);
  
  if (ret_val == GETSOCKNAME_ERR)
    perror("s_socket"), exit(EXIT_FAILURE);
}

void send_pkt(conn *Conn, pkt *Pkt) {
  int flags = SENDTO_FLAGS;

  if (Conn != NULL && Pkt != NULL && Pkt->datagram != NULL) {
      s_sendto(Conn->sockfd, Pkt->datagram, Pkt->datagram_len, flags,
	       (struct sockaddr *)&(Conn->remote), Conn->len);

    }

  else
    fprintf(stderr, "send_pkt argument error\n");
}

void s_sendto(int sockfd, const void *buf, size_t len, int flags,
	      const struct sockaddr *dest_addr, socklen_t addrlen) {

  int bytes_sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  
  if (bytes_sent == SENDTO_ERR)
    perror("s_sendto"), exit(EXIT_FAILURE);

}

void recv_pkt(conn *Conn, pkt *Pkt) {
  int flags = RECVFROM_FLAGS;

  if (Conn != NULL && Pkt != NULL) {
      Pkt->datagram_len = s_recvfrom(Conn->sockfd, Pkt->datagram, Pkt->mtu, flags,
	 (struct sockaddr *)&(Conn->remote), (socklen_t *)&(Conn->len));
  }
  else {
    fprintf(stderr, "recv_pkt: conn %p | pkt %p\n", Conn, Pkt);
  }
}

ssize_t s_recvfrom(int sockfd, void *buf, size_t len, int flags,
		   struct sockaddr *src_addr, socklen_t *addrlen) {
  int bytes_recvd = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  
  if (bytes_recvd == RECVFROM_ERR)
    perror("s_recvfrom"), exit(EXIT_FAILURE);

  return bytes_recvd;
}


int select_call(int socket, int seconds, int useconds)
{
  static struct timeval timeout;
  fd_set fdvar;
  int select_out;
  timeout.tv_sec = seconds;
  timeout.tv_usec = useconds;
  FD_ZERO(&fdvar);
  FD_SET(socket, &fdvar);
  select_out = select(socket+1, (fd_set *)&fdvar, (fd_set *)0, (fd_set *)0, &timeout);

  if (FD_ISSET(socket, &fdvar)) {
    return 1;
  }

  else if (select_out < 0) {
    perror("select_call");
    exit(EXIT_FAILURE);
  }
  
  else
    return 0;
}

pkt *pkt_alloc(uint32_t mtu) {
  pkt *Pkt = (pkt *)malloc(sizeof(pkt));
  Pkt->mtu = mtu;
  return Pkt;
}
