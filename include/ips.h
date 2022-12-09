#ifndef IPS_H
#define IPS_H

#include "sniffer.h"

void ip(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length);

void ipv6(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length);

#endif