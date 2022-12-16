#ifndef ETHERNET_H
#define ETHERNET_H

#include "sniffer.h"

/**
 * @brief Function that traduces the type of the ethernet header from a number to a string
 *
 * @param type
 * @return char*
 */
char *eth_type(uint16_t type);

/**
 * @brief Function that analyses the ethernet header
 *
 * @param packet
 * @param offset
 * @param ether_type
 */
void ethernet(const u_char *packet, int *offset, uint16_t *ether_type);

#endif