#include "dns.h"

extern int verbose;

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
    case 252:
        return "AXFR";
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
    }
}

void dns(const u_char *packet, int *offset) {
    struct dnshdr *dns = (struct dnshdr *)(packet + *offset);
    int dns_start = *offset;
    *offset += sizeof(struct dnshdr);
    if (verbose >= 2) {
        printf("id : %d, ", ntohs(dns->id));
        printf("%s, ", dns->qr ? "response" : "query");
        if (verbose >= 3) {
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
        }
        printf("qdcount : %d, ", ntohs(dns->qdcount));
        uint16_t ancount = ntohs(dns->ancount);
        printf("ancount : %d, ", ancount);
        uint16_t nscount = ntohs(dns->nscount);
        printf("nscount : %d, ", nscount);
        uint16_t arcount = ntohs(dns->arcount);
        printf("arcount : %d ", arcount);

        if (verbose == 2)
            printf("\n");

        if (verbose >= 3) {
            /* Question */
            uint8_t dom_len;
            printf("\n\nQuestion : \n");
            /* Display the domain name (no compression in it for question) */
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
                printf(", \n\nAnswer(s) : \n");
            else
                printf("\n");
            for (int r = 0; r < ancount + nscount + arcount; r++) {
                if (r == ancount && nscount > 0)
                    printf("\nAuthority Record(s) : \n");
                else if (r == ancount + nscount)
                    printf("\nAdditional Record(s) : \n");

                /* Display the domain name */
                if (packet[*offset] == 0xc0) { // If the first byte is 0xc0, it's a pointer to a previously seen domain name
                    uint8_t pointer = packet[*offset + 1];
                    *offset += 2;
                    dns_pointer(packet, dns_start, pointer); // Use a previously seen domain name part with it offset in the DNS layer
                } else {
                    if (packet[*offset] == 0x00) { // For OPT additional record
                        (*offset)++;
                    }
                    while (packet[*offset] != 0x00) { // Display the domain name which can contain compressed parts
                        if (packet[*offset] == 0xc0) {
                            uint8_t pointer = packet[*offset + 1];
                            *offset += 2;
                            dns_pointer(packet, dns_start, pointer);
                            break;
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
                type = packet[*offset] << 8; // Read a 16 bits value
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

                /* Switch to choose which procedure to apply to display correctly the DNS record */
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
                        }
                    }
                    printf("  ");
                    int rname_start = tmp_off - *offset + 1;
                    for (int i = rname_start; i < rdlength - 5; i++) { // -5 for the 5 bytes of the SOA record
                        if (packet[*offset + i] == 0xc0) {
                            printf(".");
                            uint8_t pointer = packet[*offset + i + 1];
                            dns_pointer(packet, dns_start, pointer);
                            i++;
                        } else {
                            if (i == rname_start) // To not print a dot before the name
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
                case 2: // Same than type 12
                case 5:
                case 12:
                    for (int i = 0; i < rdlength; i++) {
                        if (packet[*offset + i] == 0xc0) {
                            printf(".");
                            uint8_t pointer = packet[*offset + i + 1];
                            dns_pointer(packet, dns_start, pointer);
                            i++;
                        } else {
                            if (i == 0) // To not print a dot before the name
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
                *offset += rdlength;
                printf("\n");
            }
        }
    }
    printf(reset);
}