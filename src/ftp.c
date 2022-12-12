#include "ftp.h"

extern int verbose;

void ftp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "FTP : ");
    if (*sport == 21 || *dport == 21) {
        printf("command : ");
        if (*tcp_psh) {
            for (;;) {
                printf("%c", packet[*offset]);
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    } else {
        printf("data : ");
        if (*tcp_psh) {
            for (;;) {
                printf(isprint(packet[*offset]) ? "%c" : ".", packet[*offset]); // Utile ?
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    }
    printf("\n" reset);
}
