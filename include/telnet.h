#ifndef TELNET_H
#define TELNET_H

#include "sniffer.h"

void telnet(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif