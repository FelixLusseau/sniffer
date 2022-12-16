#ifndef TCP_H
#define TCP_H

#include "sniffer.h"

/**
 * @brief Function that analyses the TCP header
 *
 * @param packet
 * @param offset
 * @param sport
 * @param dport
 * @param tcp_psh
 */
void tcp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh);

#endif