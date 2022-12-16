#ifndef HTTP_H
#define HTTP_H

#include "sniffer.h"

/**
 * @brief Function that analyses the HTTP application layer
 *
 * @param packet
 * @param offset
 * @param tcp_psh
 * @param length
 */
void http(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif