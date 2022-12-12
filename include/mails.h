#ifndef MAILS_H
#define MAILS_H

#include "sniffer.h"

void smtp(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

void pop3(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

void imap(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length);

#endif