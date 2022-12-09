#include "mails.h"

void smtp(const u_char *packet, int *offset, uint16_t *tcp_psh /* , uint16_t *length */) {
    printf(MAG "SMTP : ");
    if (*tcp_psh) {
        while (packet[*offset] != 0x0d || packet[*offset + 1] != 0x0a) { // à vérifier
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".",
                   packet[*offset]);
            (*offset)++;
        }
    }
    printf("\n" reset);
}

void pop3(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "POP3 : ");
    if (*tcp_psh) {
        for (;;) {
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".",
                   packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}

void imap(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "IMAP : ");
    if (*tcp_psh) {
        for (;;) {
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".",
                   packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}