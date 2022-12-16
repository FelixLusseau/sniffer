#ifndef FTP_H
#define FTP_H

#include "sniffer.h"

/**
 * @brief Function that analyses the FTP application layer
 *
 * @param packet
 * @param offset
 * @param sport
 * @param dport
 * @param tcp_psh
 * @param length
 */
void ftp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh, uint16_t *length);

#endif