#ifndef TCP_H
#define TCP_H

#include "sniffer.h"

void tcp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh);

#endif