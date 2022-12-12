#include "tcp.h"

extern int verbose;

void tcp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh) {
    printf(BLU "TCP : ");
    struct tcphdr *tcp = (struct tcphdr *)(packet + *offset);
    uint16_t hdrlen = tcp->doff * 4;
    *offset += MAX(sizeof(struct tcphdr), hdrlen); // ??
    *sport = ntohs(tcp->source);
    *dport = ntohs(tcp->dest);
    *tcp_psh = tcp->psh;
    if (verbose >= 2) {
        printf("source port : %d, ", *sport);
        printf("dest port : %d", *dport);
    }
    if (verbose >= 3) {
        printf(", seq : %u, ", tcp->seq);
        printf("ack_seq : %u, ", tcp->ack_seq);
        printf("header len : %d, ", hdrlen);
        printf("fin : %d, ", tcp->fin);
        printf("syn : %d, ", tcp->syn);
        printf("rst : %d, ", tcp->rst);
        printf("psh : %d, ", *tcp_psh);
        printf("ack : %d, ", tcp->ack);
        printf("urg : %d, ", tcp->urg);
        printf("window : %d, ", ntohs(tcp->window));
        printf("check : %d, ", ntohs(tcp->check));
        printf("urg_ptr : %d", ntohs(tcp->urg_ptr));
    }
    printf("\n" reset);
}