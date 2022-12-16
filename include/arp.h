#ifndef ARP_H
#define ARP_H

#include "sniffer.h"

/**
 * @brief Function that analyses the ARP header
 *
 * @param packet
 * @param offset
 */
void arp(const u_char *packet, int *offset);

#endif