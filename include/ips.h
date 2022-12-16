#ifndef IPS_H
#define IPS_H

#include "sniffer.h"

/**
 * @brief Function that analyses the IPv4 header
 *
 * @param packet
 * @param offset
 * @param protocol
 * @param length
 */
void ip(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length);

/**
 * @brief Function that analyses the IPv6 header
 *
 * @param packet
 * @param offset
 * @param protocol
 * @param length
 */
void ipv6(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length);

#endif