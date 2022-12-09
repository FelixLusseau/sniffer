#include "http.h"

void http(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "HTTP : ");
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