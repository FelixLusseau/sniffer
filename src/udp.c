#include "udp.h"

extern int verbose;

void udp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport) {
    printf(BLU "UDP : ");
    struct udphdr *udp = (struct udphdr *)(packet + *offset);
    *offset += sizeof(struct udphdr);
    *sport = ntohs(udp->source);
    *dport = ntohs(udp->dest);
    if (verbose >= 2) {
        printf("source port : %u, ", *sport);
        printf("dest port : %u, ", *dport);
        printf("len : %u, ", udp->len);
        printf("check : %u\n", udp->check);
    }
    printf(reset);
}