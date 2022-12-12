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
        if (hdrlen > sizeof(struct tcphdr)) {
            printf(", options : [ ");
            while (*offset < tcp_offset + hdrlen) {
                uint8_t type = packet[*offset];
                (*offset)++;
                uint8_t len = packet[*offset];
                (*offset)++;
                if (type == 0x01) {
                    printf("nop, ");
                } else if (type == 0x02) {
                    printf("mss : %d, ", ntohs(*(uint16_t *)(packet + *offset)));
                    (*offset) += 2;
                } else if (type == 0x03) {
                    printf("window scale : %d, ", packet[*offset]);
                    (*offset)++;
                } else if (type == 0x04) {
                    printf("SACK permitted, ");
                    (*offset) += 2;
                } else if (type == 0x05) {
                    printf("SACK, ");
                    (*offset) += 2;
                } else if (type == 0x08) {
                    printf("timestamp, ");
                    (*offset) += 8;
                } else if (type == 0x0a) {
                    printf("md5, ");
                    (*offset) += 18;
                } else if (type == 0x0b) {
                    printf("fast open, ");
                    (*offset) += 2;
                } else if (type == 0x0c) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x0d) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x0e) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x0f) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x10) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x11) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x12) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x13) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x14) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                } else if (type == 0x15) {
                    printf("exp fast open, ");
                    (*offset) += 2;
                }
            }
            printf("\e[2D ]");
        }
    } else {
        *offset += hdrlen - sizeof(struct tcphdr);
    }
    if (verbose > 1)
        printf("\n" reset);
}