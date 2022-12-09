#include "ethernet.h"

extern int verbose;

char *eth_type(uint16_t type) {
    switch (htons(type)) {
    case ETHERTYPE_ARP:
        return "ARP";
    case ETHERTYPE_IP:
        return "IP";
    case ETHERTYPE_IPV6:
        return "IPV6";
    case ETHERTYPE_VLAN:
        return "VLAN";
    case ETHERTYPE_LOOPBACK:
        return "LOOPBACK";
    default:
        return "UNKNOWN";
    }
}

void ethernet(const u_char *packet, int *offset, uint16_t *ether_type) {
    printf(GRN "Ethernet : ");
    struct ether_header *ethernet = (struct ether_header *)packet;
    *offset += sizeof(struct ether_header);
    *ether_type = ethernet->ether_type;
    if (verbose >= 2) {
        printf("type : %s, ", eth_type(ethernet->ether_type));
        printf("MAC source : %s, ", ether_ntoa((struct ether_addr *)&ethernet->ether_shost));
        printf("MAC dest : %s\n", ether_ntoa((struct ether_addr *)&ethernet->ether_dhost));
    }
    printf(reset);
}