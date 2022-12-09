#ifndef UDP_H
#define UDP_H

#include "sniffer.h"

void udp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport);

#endif