#ifndef DNS_H
#define DNS_H

#include "sniffer.h"

struct dnshdr {
    uint16_t id;
    // uint16_t flags;
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t op : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t z : 3;
    uint8_t ra : 1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/**
 * @brief Function that traduces the type of the DNS header from a number to a string
 *
 * @param type
 * @return char*
 */
char *dns_type(uint16_t type);

/**
 * @brief Function that traduces the class of the DNS header from a number to a string
 *
 * @param class
 * @return
 */
char *dns_class(uint16_t class);

/**
 * @brief Function that is used to decompress the names in the DNS packet
 * by following the pointers to already transferred names
 *
 * @param packet
 * @param dns_offset
 * @param pointer
 */
void dns_pointer(const u_char *packet, int dns_offset, uint8_t pointer);

/**
 * @brief Function that analyses the DNS application layer
 *
 * @param packet
 * @param offset
 */
void dns(const u_char *packet, int *offset);

#endif