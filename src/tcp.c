#include "tcp.h"

extern int verbose;

void tcp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh) {
    printf(BLU "TCP : ");
    struct tcphdr *tcp = (struct tcphdr *)(packet + *offset);
    uint16_t hdrlen = tcp->doff * 4;
    int tcp_offset = *offset;
    *offset += sizeof(struct tcphdr);
    *sport = ntohs(tcp->source);
    *dport = ntohs(tcp->dest);
    *tcp_psh = tcp->psh;
    if (verbose >= 2) {
        printf("source port : %d, ", *sport);
        printf("dest port : %d, ", *dport);
        printf("seq : %u, ", tcp->seq);
        printf("ack_seq : %u", tcp->ack_seq);
    }
    if (verbose >= 3) {
        printf(", header len : %d, ", hdrlen);
        printf("fin : %d, ", tcp->fin);
        printf("syn : %d, ", tcp->syn);
        printf("rst : %d, ", tcp->rst);
        printf("psh : %d, ", *tcp_psh);
        printf("ack : %d, ", tcp->ack);
        printf("urg : %d, ", tcp->urg);
        printf("window : %d, ", ntohs(tcp->window));
        printf("check : %d, ", ntohs(tcp->check));
        printf("urg_ptr : %d", ntohs(tcp->urg_ptr));
        if (hdrlen > sizeof(struct tcphdr)) {
            printf(", options : [ ");
            while (*offset < tcp_offset + hdrlen) {
                uint8_t type = packet[*offset];
                (*offset)++;
                uint8_t len = packet[*offset];
                (*offset)++;
                if (type == 0x01) {
                    printf("nop, ");
                    (*offset)--;
                    continue;
                } else if (type == 0x02) {
                    printf("mss : %d, ", ntohs(*(uint16_t *)(packet + *offset)));
                } else if (type == 0x03) {
                    printf("window scale : %d, ", packet[*offset]);
                } else if (type == 0x04) {
                    printf("SACK permitted, ");
                } else if (type == 0x05) {
                    printf("SACK, ");
                } else if (type == 0x08) {
                    printf("timestamp, ");
                } else if (type == 0x0a) {
                    printf("md5, ");
                }
                *offset += len - 2;
            }
            printf("\e[2D ]");
        }
    } else {
        *offset += hdrlen - sizeof(struct tcphdr);
    }
    if (verbose > 1)
        printf("\n" reset);
}