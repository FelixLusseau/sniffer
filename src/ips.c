#include "ips.h"

extern int verbose;

void ip(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length) {
    printf(RED "IP : ");
    struct iphdr *ip = (struct iphdr *)(packet + *offset);
    *offset += sizeof(struct iphdr);
    *protocol = ip->protocol;
    *length = htons(ip->tot_len) + sizeof(struct ether_header);
    if (verbose >= 3) {
        printf("version : %d, ", ip->version);
        printf("ihl : %d, ", ip->ihl);
        printf("tos : %d, ", ip->tos);
        printf("tot_len : %d, ", *length);
        printf("id : %d, ", htons(ip->id));
        printf("frag_off : %d, ", ip->frag_off);
        printf("ttl : %d, ", ip->ttl);
        printf("protocol : %d, ", *protocol);
        printf("check : %d, ", htons(ip->check));
    }
    if (verbose >= 2) {
        printf("source IP : %s, ", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("destination IP : %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    }
    printf(reset);
}

void ipv6(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length) {
    printf(RED "IPv6 : ");
    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + *offset);
    *offset += sizeof(struct ip6_hdr);
    char ip6_src[INET6_ADDRSTRLEN];
    char ip6_dst[INET6_ADDRSTRLEN];
    *protocol = ip6->ip6_nxt;
    *length = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr) + sizeof(struct ether_header);
    if (verbose >= 3) {
        printf("version : %d, ", ip6->ip6_vfc >> 4);
        printf("traffic class : %d, ", ip6->ip6_vfc & 0x0f);
        printf("flow label : %u, ", ip6->ip6_flow);
        printf("payload length : %d, ", *length);
        printf("next header : %d, ", ip6->ip6_nxt);
        printf("hop limit (TTL) : %d, ", ip6->ip6_hlim);
    }
    if (verbose >= 2) {
        printf("source address : %s, ", inet_ntop(AF_INET6, &ip6->ip6_src, ip6_src, sizeof(ip6_src)));
        printf("destination address : %s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, ip6_dst, sizeof(ip6_dst)));
    }
    printf(reset);
}