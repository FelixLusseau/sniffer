#include "bootp.h"

extern int verbose;

void bootp_dhcp(const u_char *packet, int *offset) {
    printf(MAG "Bootp : ");
    struct bootp *bootp = (struct bootp *)(packet + *offset);
    *offset += sizeof(struct bootp) - 64; // -64 pour les vendors qui peuvent dépasser
    if (verbose >= 3) {
        printf("op : %d, ", bootp->bp_op);
        printf("htype : %d, ", bootp->bp_htype);
        printf("hlen : %d, ", bootp->bp_hlen);
        printf("hops : %d, ", bootp->bp_hops);
        printf("xid : %u, ", bootp->bp_xid);
        printf("secs : %d, ", bootp->bp_secs);
        printf("flags : %d, ", bootp->bp_flags);
        printf("ciaddr : %s, ", inet_ntoa(*(struct in_addr *)&bootp->bp_ciaddr));
        printf("yiaddr : %s, ", inet_ntoa(*(struct in_addr *)&bootp->bp_yiaddr));
        printf("siaddr : %s, ", inet_ntoa(*(struct in_addr *)&bootp->bp_siaddr));
        printf("giaddr : %s, ", inet_ntoa(*(struct in_addr *)&bootp->bp_giaddr));
        printf("chaddr : %s, ", ether_ntoa((struct ether_addr *)&bootp->bp_chaddr));
        printf("sname : %s, ", bootp->bp_sname);
        printf("file : %s, ", bootp->bp_file);
        printf("\n");
    }

    /* BOOTP options */
    if (bootp->bp_vend[0] == 99 && bootp->bp_vend[1] == 130 && bootp->bp_vend[2] == 83 && bootp->bp_vend[3] == 99) {
        *offset += 4;
        printf("DHCP : ");
        while (packet[*offset] != 0xff) {
            uint8_t type = packet[*offset];
            (*offset)++;
            uint8_t len = packet[*offset];
            (*offset)++;
            if (verbose >= 2) {
                switch (type) {
                case 53:
                    printf("type : %d, ", packet[*offset]);
                    break;
                case 54:
                    printf("server identifier : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 51:
                    printf("lease time : %u, ", *(uint32_t *)&packet[*offset]);
                    break;
                case 1:
                    printf("subnet mask : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 3:
                    printf("router : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 6:
                    printf("DNS : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 15:
                    printf("domain : %s, ", &packet[*offset]);
                    break;
                case 28:
                    printf("broadcast address : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 50:
                    printf("requested IP : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 12:
                    printf("host name : %s, ", &packet[*offset]);
                    break;
                case 44:
                    printf("subnet mask : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 46:
                    printf("MTU : %d, ", *(uint16_t *)&packet[*offset]);
                    break;
                case 252:
                    printf("PXE : %s, ", &packet[*offset]);
                    break;
                default:
                    printf("type : %d, ", type);
                    break;
                }
            }
            *offset += len;
        }
    }
    printf(reset "\n");
}