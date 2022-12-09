#include "arp.h"

extern int verbose;

void arp(const u_char *packet, int *offset) {
    printf(RED "ARP : ");
    struct ether_arp *arp = (struct ether_arp *)(packet + *offset);
    *offset += sizeof(struct ether_arp);
    if (verbose >= 2) {
        printf("arp_hrd : %d, ", ntohs(arp->arp_hrd));
        printf("arp_pro : %d, ", ntohs(arp->arp_pro));
        printf("arp_hln : %d, ", arp->arp_hln);
        printf("arp_pln : %d, ", arp->arp_pln);
        printf("arp_op : %d, ", ntohs(arp->arp_op));
        printf("arp_sha : %s, ", ether_ntoa((struct ether_addr *)&arp->arp_sha));
        printf("arp_spa : %s, ", inet_ntoa(*(struct in_addr *)&arp->arp_spa));
        printf("arp_tha : %s, ", ether_ntoa((struct ether_addr *)&arp->arp_tha));
        printf("arp_tpa : %s\n", inet_ntoa(*(struct in_addr *)&arp->arp_tpa));
    }
    printf(reset);
}