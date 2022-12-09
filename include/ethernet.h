#ifndef ETHERNET_H
#define ETHERNET_H

#include "sniffer.h"

char *eth_type(uint16_t type);

void ethernet(const u_char *packet, int *offset, uint16_t *ether_type);

#endif