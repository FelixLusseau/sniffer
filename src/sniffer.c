#include "../include/sniffer.h"

long int counter;
int verbose = 1;
char *filter = NULL;

struct dnshdr {
    uint16_t id;
    // uint16_t flags;
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t op : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t z : 3;
    uint8_t ra : 1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

char *dns_type(uint16_t type) {
    switch (type) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 12:
        return "PTR";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    case 33:
        return "SRV";
    case 41:
        return "OPT";
    case 255:
        return "ANY";
    default:
        return "UNKNOWN";
    }
}

char *dns_class(uint16_t class) {
    switch (class) {
    case 1:
        return "IN";
    case 2:
        return "CS";
    case 3:
        return "CH";
    case 4:
        return "HS";
    case 255:
        return "ANY";
    default:
        return "UNKNOWN";
    }
}

void dns_pointer(const u_char *packet, int dns_offset, uint8_t pointer) {
    while (packet[dns_offset + pointer] != 0x00) {
        if (packet[dns_offset + pointer] == 0xc0) {
            uint8_t new_pointer = packet[dns_offset + pointer + 1];
            pointer += 2;
            dns_pointer(packet, dns_offset, new_pointer);
            break;
        }
        uint8_t dom_len = packet[dns_offset + pointer];
        pointer++;
        char buf[64] = {0};
        int m;
        for (m = 0; m < dom_len && m < 64; m++) {
            buf[m] = packet[dns_offset + pointer + m];
        }
        buf[m] = '\0';
        printf("%s", buf);
        pointer += dom_len;
        printf(".");
        // printf("ok");
    }
}

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

char *proto(uint8_t protocol) {
    switch (protocol) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "UNKNOWN";
    }
}

void headers(const struct pcap_pkthdr *header) {
    printf(YEL "Headers : ");
    if (verbose >= 2) {
        time_t time = header->ts.tv_sec;
        char *time_str = ctime(&time);
        time_str[strlen(time_str) - 1] = '\0';
        printf("time : %s, ", time_str);
        printf("caplen : %d, len : %d\n", header->caplen, header->len);
    }
    printf(reset);
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

void ip(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length) {
    printf(RED "IP : ");
    struct iphdr *ip = (struct iphdr *)(packet + *offset);
    *offset += sizeof(struct iphdr);
    *protocol = ip->protocol;
    if (verbose >= 2) {
        printf("version : %d, ", ip->version);
        printf("ihl : %d, ", ip->ihl);
        printf("tos : %d, ", ip->tos);
        *length = htons(ip->tot_len) + sizeof(struct ether_header);
        printf("tot_len : %d, ", *length);
        printf("id : %d, ", htons(ip->id));
        printf("frag_off : %d, ", ip->frag_off);
        printf("ttl : %d, ", ip->ttl);
        printf("protocol : %d, ", *protocol);
        printf("check : %d, ", htons(ip->check));
        printf("IP source : %s, ", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("IP dest : %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    }
    printf(reset);
}

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

void ipv6(const u_char *packet, int *offset, u_int8_t *protocol, uint16_t *length) {
    printf(RED "IPv6 : ");
    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + *offset);
    *offset += sizeof(struct ip6_hdr);
    char ip6_src[INET6_ADDRSTRLEN];
    char ip6_dst[INET6_ADDRSTRLEN];
    *protocol = ip6->ip6_nxt;
    if (verbose >= 2) {
        printf("version : %d, ", ip6->ip6_vfc >> 4);
        printf("traffic class : %d, ", ip6->ip6_vfc & 0x0f);
        printf("flow label : %u, ", ip6->ip6_flow);
        *length = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr) + sizeof(struct ether_header);
        printf("payload length : %d, ", *length);
        printf("next header : %d, ", ip6->ip6_nxt);
        printf("hop limit (TTL) : %d, ", ip6->ip6_hlim);
        printf("source address : %s, ", inet_ntop(AF_INET6, &ip6->ip6_src, ip6_src, sizeof(ip6_src)));
        printf("destination address : %s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, ip6_dst, sizeof(ip6_dst)));
    }
    printf(reset);
}

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

void tcp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh) {
    printf(BLU "TCP : ");
    struct tcphdr *tcp = (struct tcphdr *)(packet + *offset);
    uint16_t hdrlen = tcp->doff * 4;
    *offset += MAX(sizeof(struct tcphdr), hdrlen); // ??
    *sport = ntohs(tcp->source);
    *dport = ntohs(tcp->dest);
    if (verbose >= 2) {
        printf("source port : %d, ", *sport);
        printf("dest port : %d, ", *dport);
        printf("seq : %u, ", tcp->seq);
        printf("ack_seq : %u, ", tcp->ack_seq);
        printf("header len : %d, ", hdrlen);
        printf("fin : %d, ", tcp->fin);
        printf("syn : %d, ", tcp->syn);
        printf("rst : %d, ", tcp->rst);
        *tcp_psh = tcp->psh;
        printf("psh : %d, ", *tcp_psh);
        printf("ack : %d, ", tcp->ack);
        printf("urg : %d, ", tcp->urg);
        printf("window : %d, ", ntohs(tcp->window));
        printf("check : %d, ", ntohs(tcp->check));
        printf("urg_ptr : %d\n", ntohs(tcp->urg_ptr));
    }
    printf(reset);
}

void bootp_dhcp(const u_char *packet, int *offset) {
    printf(MAG "Bootp : ");
    struct bootp *bootp = (struct bootp *)(packet + *offset);
    *offset += sizeof(struct bootp) - 64; // -64 pour les vendors qui peuvent dépasser
    if (verbose >= 2) {
        printf("op : %d, ", bootp->bp_op);
        printf("htype : %d, ", bootp->bp_htype);
        printf("hlen : %d, ", bootp->bp_hlen);
        printf("hops : %d, ", bootp->bp_hops);
        printf("xid : %d, ", bootp->bp_xid);
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
                    printf("lease time : %d, ", *(uint32_t *)&packet[*offset]);
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

void dns(const u_char *packet, int *offset) {
    printf(MAG "DNS : ");
    struct dnshdr *dns = (struct dnshdr *)(packet + *offset);
    int dns_start = *offset;
    *offset += sizeof(struct dnshdr);
    if (verbose >= 2) {
        printf("id : %d, ", htons(dns->id));
        printf("%s, ", dns->qr ? "response" : "query");
        printf("opcode : %d, ", dns->op);
        printf("flags : [");
        printf("%s", dns->aa ? " authoritative" : "");
        printf("%s", dns->tc ? " truncated" : "");
        printf("%s", dns->rd ? " recursion_desired" : "");
        printf("%s", dns->ra ? " recursion_available" : "");
        printf(" ], ");
        if (dns->rcode == 0)
            printf("no error, ");
        else if (dns->rcode == 1)
            printf("format error, ");
        else if (dns->rcode == 2)
            printf("server failure, ");
        else if (dns->rcode == 3)
            printf("name error, ");
        else if (dns->rcode == 4)
            printf("not implemented, ");
        else if (dns->rcode == 5)
            printf("refused, ");
        printf("qdcount : %d, ", htons(dns->qdcount));
        uint16_t ancount = htons(dns->ancount);
        printf("ancount : %d, ", ancount);
        printf("nscount : %d, ", htons(dns->nscount));
        printf("arcount : %d, ", htons(dns->arcount));

        /* Question */
        uint8_t dom_len;
        printf("\nQuestion : \n");
        while (packet[*offset] != 0x00) {
            dom_len = packet[*offset];
            (*offset)++;
            char buf[64];
            int m;
            for (m = 0; m < dom_len && m < 64; m++) {
                buf[m] = packet[*offset + m];
            }
            buf[m] = '\0';
            printf("%s", buf);
            *offset += dom_len;
            printf(".");
        }
        (*offset)++;
        uint16_t type = packet[*offset] << 8;
        type += packet[*offset + 1];
        *offset += 2;
        uint16_t class = packet[*offset] << 8;
        class += packet[*offset + 1];
        *offset += 2;
        printf("\t%s\t%s", dns_class(class), dns_type(type));

        /* Answer */
        if (ancount)
            printf(", \nAnswer(s) : \n");
        else
            printf("\n");
        for (int r = 0; r < ancount; r++) {
            if (packet[*offset] == 0xc0) {
                uint8_t pointer = packet[*offset + 1];
                *offset += 2;
                dns_pointer(packet, dns_start, pointer);
            } else {
                while (packet[*offset] != 0x00) {
                    if (packet[*offset] == 0xc0) {
                        uint8_t pointer = packet[*offset + 1];
                        *offset += 2;
                        dns_pointer(packet, dns_start, pointer);
                    }
                    dom_len = packet[*offset];
                    (*offset)++;
                    char buf[64] = {0};
                    int m;
                    for (m = 0; m < dom_len && m < 64; m++) {
                        buf[m] = packet[*offset + m];
                    }
                    buf[m] = '\0';
                    printf("%s", buf);
                    *offset += dom_len;

                    printf(".");
                }
            }
            type = packet[*offset] << 8;
            type += packet[*offset + 1];
            *offset += 2;
            class = packet[*offset] << 8;
            class += packet[*offset + 1];
            *offset += 2;
            uint32_t ttl = packet[*offset] << 24;
            ttl += packet[*offset + 1] << 16;
            ttl += packet[*offset + 2] << 8;
            ttl += packet[*offset + 3];
            *offset += 4;
            uint16_t rdlength = packet[*offset] << 8;
            rdlength += packet[*offset + 1];
            *offset += 2;

            printf("  %d", ttl);
            printf("\t%s\t%s ", dns_class(class), dns_type(type));
            printf("\t");
            switch (type) {
            case 1:
                printf("%d.%d.%d.%d", packet[*offset], packet[*offset + 1], packet[*offset + 2], packet[*offset + 3]);
                break;
            case 6:
                int tmp_off = *offset;
                if (packet[tmp_off] == 0xc0) {
                    uint8_t pointer = packet[tmp_off + 1];
                    tmp_off += 2;
                    dns_pointer(packet, dns_start, pointer);
                } else {
                    while (packet[tmp_off] != 0x00) {
                        if (packet[tmp_off] == 0xc0) {
                            uint8_t pointer = packet[tmp_off + 1];
                            tmp_off += 2;
                            dns_pointer(packet, dns_start, pointer);
                        }
                        dom_len = packet[tmp_off];
                        // printf("dl:%x", packet[tmp_off - 2]);
                        tmp_off++;
                        char buf[64] = {0};
                        int m;
                        for (m = 0; m < dom_len && m < 64; m++) {
                            buf[m] = packet[tmp_off + m];
                        }
                        buf[m] = '\0';
                        printf("%s", buf);
                        tmp_off += dom_len;

                        printf(".");
                        // printf("'%x'", packet[tmp_off]);
                    }
                }
                // printf("calc %d", tmp_off - *offset);
                printf("  ");
                int rname_start = tmp_off - *offset + 1;
                for (int i = rname_start; i < rdlength - 5; i++) { // -5 for the 5 bytes of the SOA record
                    if (packet[*offset + i] == 0xc0) {
                        printf(".");
                        uint8_t pointer = packet[*offset + i + 1];
                        dns_pointer(packet, dns_start, pointer);
                        i++;
                    } else {
                        if (i == rname_start) // ne pas afficher un point au début
                            i++;
                        printf(isprint(packet[*offset + i]) ? "%c" : ".", packet[*offset + i]);
                    }
                }
                tmp_off += rdlength - 2 * rname_start - 5 + 1;
                uint32_t serial = packet[tmp_off] << 24;
                serial += packet[tmp_off + 1] << 16;
                serial += packet[tmp_off + 2] << 8;
                serial += packet[tmp_off + 3];
                tmp_off += 4;
                printf("  %u", serial);
                uint32_t refresh = packet[tmp_off] << 24;
                refresh += packet[tmp_off + 1] << 16;
                refresh += packet[tmp_off + 2] << 8;
                refresh += packet[tmp_off + 3];
                tmp_off += 4;
                printf("  %u", refresh);
                uint32_t retry = packet[tmp_off] << 24;
                retry += packet[tmp_off + 1] << 16;
                retry += packet[tmp_off + 2] << 8;
                retry += packet[tmp_off + 3];
                tmp_off += 4;
                printf("  %u", retry);
                uint32_t expire = packet[tmp_off] << 24;
                expire += packet[tmp_off + 1] << 16;
                expire += packet[tmp_off + 2] << 8;
                expire += packet[tmp_off + 3];
                tmp_off += 4;
                printf("  %u", expire);
                uint32_t minimum = packet[tmp_off] << 24;
                minimum += packet[tmp_off + 1] << 16;
                minimum += packet[tmp_off + 2] << 8;
                minimum += packet[tmp_off + 3];
                tmp_off += 4;
                printf("  %u", minimum);
                break;
            case 2:
            case 5:
            case 12:
                for (int i = 0; i < rdlength; i++) {
                    if (packet[*offset + i] == 0xc0) {
                        printf(".");
                        uint8_t pointer = packet[*offset + i + 1];
                        dns_pointer(packet, dns_start, pointer);
                        i++;
                    } else {
                        if (i == 0) // ne pas afficher un point au début
                            i++;
                        printf(isprint(packet[*offset + i]) ? "%c" : ".", packet[*offset + i]);
                    }
                }
                break;
            case 15:
                uint16_t mx_priority = packet[*offset] << 8;
                mx_priority += packet[*offset + 1];
                printf("%d\t", mx_priority);
                for (int i = 2; i < rdlength; i++) {
                    if (packet[*offset + i] == 0xc0) {
                        printf(".");
                        uint8_t pointer = packet[*offset + i + 1];
                        dns_pointer(packet, dns_start, pointer);
                        i++;
                    } else {
                        if (i == 2)
                            i++;
                        printf(isprint(packet[*offset + i]) ? "%c" : ".", packet[*offset + i]);
                    }
                }
                break;
            case 16:
                for (int i = 0; i < rdlength; i++) {
                    printf("%c", packet[*offset + i]);
                }
                break;
            case 28:
                for (int i = 0; i < rdlength; i++) {
                    printf("%02x", packet[*offset + i]);
                    if (i < rdlength - 1 && i % 2 == 1)
                        printf(":");
                }
                break;
            default:
                printf("%s", &packet[*offset]);
                break;
            }
            // printf("rdlength : %d, ", rdlength);
            *offset += rdlength;
            printf("\n");
        }
    }
    printf(reset);
}

void ftp(const u_char *packet, int *offset, uint16_t *sport, uint16_t *dport, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "FTP : ");
    if (*sport == 21 || *dport == 21) {
        printf("command : ");
        if (*tcp_psh) {
            for (;;) {
                printf("%c", packet[*offset]);
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    } else {
        printf("data : ");
        if (*tcp_psh) {
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

void smtp(const u_char *packet, int *offset, uint16_t *tcp_psh /* , uint16_t *length */) {
    printf(MAG "SMTP : ");
    if (*tcp_psh) {
        while (packet[*offset] != 0x0d || packet[*offset + 1] != 0x0a) { // à vérifier
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
            (*offset)++;
        }
    }
    printf("\n" reset);
}

void http(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "HTTP : ");
    if (*tcp_psh) {
        for (;;) {
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}

void pop3(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "POP3 : ");
    if (*tcp_psh) {
        for (;;) {
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}

void imap(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "IMAP : ");
    if (*tcp_psh) {
        for (;;) {
            printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
            (*offset)++;
            if (*offset >= *length)
                break;
        }
    }
    printf("\n" reset);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    char *sad = "         nothing to analyze :'(";

    printf("Packet %ld : \n", ++counter);
    int offset = 0;
    headers(header);

    uint16_t ether_type;
    ethernet(packet, &offset, &ether_type);

    uint8_t protocol;
    uint16_t sport;
    uint16_t dport;
    uint16_t length;

    switch (htons(ether_type)) {
    case (ETHERTYPE_IP):
        ip(packet, &offset, &protocol, &length);
        break;
    case (ETHERTYPE_ARP):
        arp(packet, &offset);
        if (verbose == 1)
            printf("\n");
        printf("\n------------------------------------------------------------------------------\n\n");
        return;
    case (ETHERTYPE_REVARP):
        printf(RED "RARP : \n" reset); // = ARP ?
        if (verbose == 1)
            printf("\n");
        printf("\n------------------------------------------------------------------------------\n\n");
        return;
    case (ETHERTYPE_IPV6):
        ipv6(packet, &offset, &protocol, &length);
        break;
    default:
        printf(RED "Unknown Protocol\n" reset);
    }
    /* if (filter && strcmp(proto(protocol), filter) != 0) {
        for (int z = 0; z < 4; z++)
            printf("\e[1F\e[2K");
        return;
    } */

    switch (protocol) {
    case 1:
        printf(BLU "ICMP ");
        printf("\n" reset);
        break;
    case 17:
        udp(packet, &offset, &sport, &dport);

        if (sport == 67 || sport == 68 || dport == 67 || dport == 68) {
            bootp_dhcp(packet, &offset);
        } else if (sport == 53 || dport == 53) {
            dns(packet, &offset);
        } else if (sport == 443 || dport == 443) {
            printf(MAG "HTTP/3 QUIC :%s\n" reset, sad);
        } else {
            printf(MAG "Unknown UDP service\n" reset);
        }
        break;
    case 6:
        uint16_t tcp_psh;
        tcp(packet, &offset, &sport, &dport, &tcp_psh);
        /* if (counter==20)
        exit(0); */
        if (sport == 21 || dport == 21 || sport == 20 || dport == 20) {
            ftp(packet, &offset, &sport, &dport, &tcp_psh, &length);
        } else if (sport == 25 || dport == 25) {
            smtp(packet, &offset, &tcp_psh /* , &length */);
        } else if (sport == 22 || dport == 22) {
            printf(MAG "SSH :%s", sad);
            printf("\n" reset);
        } else if (sport == 80 || dport == 80) {
            http(packet, &offset, &tcp_psh, &length);
        } else if (sport == 110 || dport == 110) {
            pop3(packet, &offset, &tcp_psh, &length);
        } else if (sport == 143 || dport == 143) {
            imap(packet, &offset, &tcp_psh, &length);
        } else if (sport == 443 || dport == 443) {
            printf(MAG "HTTPS :%s \n" reset, sad);
        } else if (sport == 993 || dport == 993) {
            printf(MAG "IMAPS :%s\n" reset, sad);
        } else if (sport == 995 || dport == 995) {
            printf(MAG "POP3S :%s\n" reset, sad);
        } else {
            printf(MAG "Unknown TCP service\n" reset);
        }

        break;
    case 58:
        printf(BLU "ICMPv6 ");
        printf("\n" reset);
        break;
    default:
        printf(BLU "Other protocol : %d \n" reset, protocol);
        break;
    }

    if (verbose == 1)
        printf("\n");
    printf("\n------------------------------------------------------------------------------\n\n");
    /* for (int z = 0; z < 15; z++)
        printf("\e[1F\e[2K"); */
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf(RED "Usage: %s -i interface -f filter -o offline_file -v verbose\n" reset, argv[0]);
        return 1;
    }

    int c;
    char *interface = NULL;
    char *offline_file = NULL;
    while ((c = getopt(argc, argv, "i:o:f:v:")) != -1) {
        switch (c) {
        case 'i':
            interface = optarg;
            break;
        case 'o':
            offline_file = optarg;
            break;
        case 'f':
            filter = optarg;
            break;
        case 'v':
            verbose = atoi(optarg);
            break;
        default:
            printf("Usage: %s -i interface -f filter -o offline_file -v verbose\n", argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    if (interface) {
        pcap_if_t *interfaces;
        if (pcap_findalldevs(&interfaces, errbuf) == PCAP_ERROR) {
            printf("Error: %s", errbuf);
            return 1;
        };
        printf("### Interfaces : ###\n");
        while (interfaces->next != NULL) {
            printf("- %s, \n", interfaces->name);
            interfaces = interfaces->next;
        }
    }

    if (interface == NULL && offline_file == NULL) {
        printf("Error: interface or offline_file not specified\n");
        return 1;
    }

    pcap_t *capture;

    if (interface) {

        bpf_u_int32 netaddr;
        bpf_u_int32 mask;
        if (pcap_lookupnet(interface, &netaddr, &mask, errbuf) == PCAP_ERROR) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n%s : IP %s, ", interface, inet_ntoa(*(struct in_addr *)&netaddr));
        printf("masque %s\n\n", inet_ntoa(*(struct in_addr *)&mask));

        if ((capture = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n            ### Capture on %s : ###\n\n", interface);
    }

    if (offline_file) {
        if ((capture = pcap_open_offline(offline_file, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n            ### Capture on %s : ###\n\n", offline_file); // centrer ??
    }

    if (pcap_loop(capture, -1, got_packet, NULL) == PCAP_ERROR) {
        printf("Error: %s", errbuf);
        return 1;
    }

    return 0;
}