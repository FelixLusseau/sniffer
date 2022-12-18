#include "arp.h"

extern int verbose;

void arp(const u_char *packet, int *offset) {
    printf(RED "ARP : ");
    struct ether_arp *arp = (struct ether_arp *)(packet + *offset);
    *offset += sizeof(struct ether_arp);
    if (verbose >= 3) {
        printf("ARP hardware type : %d, ", ntohs(arp->arp_hrd));
        printf("ARP protocol type : %d, ", ntohs(arp->arp_pro));
        printf("ARP hardware len : %d, ", arp->arp_hln);
        printf("ARP IP len : %d, ", arp->arp_pln);
        printf("ARP op : %d, \n", ntohs(arp->arp_op));
    }
    if (verbose >= 2) {
        printf("ARP sender MAC : %s, ", ether_ntoa((struct ether_addr *)&arp->arp_sha));
        printf("ARP sender IP : %s, ", inet_ntoa(*(struct in_addr *)&arp->arp_spa));
        printf("ARP target MAC : %s, ", ether_ntoa((struct ether_addr *)&arp->arp_tha));
        printf("ARP target IP : %s\n", inet_ntoa(*(struct in_addr *)&arp->arp_tpa));
    }
    printf(reset);
}