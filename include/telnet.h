#ifndef TELNET_H
#define TELNET_H

#include "sniffer.h"

/**
 * @brief Function that analyses the TELNET application layer
 *
 * @param packet
 * @param offset
 * @param tcp_psh
 * @param length
 */
void telnet(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif