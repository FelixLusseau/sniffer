#ifndef UDP_H
#define UDP_H

#include "sniffer.h"

/**
 * @brief Function that analyses the UDP header
 *
 * @param packet
 * @param offset
 * @param sport
 * @param dport
 */
void udp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport);

#endif