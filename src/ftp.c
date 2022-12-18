#include "ftp.h"

extern int verbose;

void ftp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh, uint16_t *length, uint16_t *data_port) {
    printf(MAG "FTP : ");
    if (*sport == 21 || *dport == 21) {
        printf("control : ");
        if (*tcp_psh) {
            /* 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2). Send the port to the main function for the next packets */
            if (packet[*offset] == '2' && packet[*offset + 1] == '2' && packet[*offset + 2] == '7') {
                *data_port = ((packet[*offset + 41] - '0') * 10 + packet[*offset + 42] - '0') * 256 +
                             ((packet[*offset + 44] - '0') * 10 + packet[*offset + 45] - '0');
            }
            for (;;) {
                printf("%c", packet[*offset]);
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    } else {
        printf("data : ");
        if (*tcp_psh && verbose >= 3) {
            for (;;) {
                printf(isprint(packet[*offset]) ? "%c" : ".", packet[*offset]);
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    }
    printf("\n" reset);
}
