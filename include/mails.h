#ifndef MAILS_H
#define MAILS_H

#include "sniffer.h"

/**
 * @brief Function that analyses the SMTP application layer
 *
 * @param packet
 * @param offset
 * @param tcp_psh
 * @param length
 */
void smtp(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

/**
 * @brief Function that analyses the POP3 application layer
 *
 * @param packet
 * @param offset
 * @param tcp_psh
 * @param length
 */
void pop3(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

/**
 * @brief Function that analyses the IMAP application layer
 *
 * @param packet
 * @param offset
 * @param tcp_psh
 * @param length
 */
void imap(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif