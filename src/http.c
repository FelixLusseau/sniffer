#include "http.h"

extern int verbose;

void http(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "HTTP : ");
    if (*tcp_psh && verbose >= 2) {
        for (;;) {
            if (packet[*offset] == '\r' && packet[*offset + 1] == '\n' && verbose < 3) // Just printing the first line
                break;
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}