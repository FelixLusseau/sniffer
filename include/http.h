#ifndef HTTP_H
#define HTTP_H

#include "sniffer.h"

void http(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif