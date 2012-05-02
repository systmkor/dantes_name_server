#include <stdlib.h>
#include <stdio.h>

#include "dns.h"
#include "conn.h"

int main(void) {
  conn *Conn;
  Conn = listening();
  process_pkts(Conn);
  return EXIT_SUCCESS;
}
