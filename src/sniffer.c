#include "sniffer.h"
#include "arp.h"
#include "bootp.h"
#include "dns.h"
#include "ethernet.h"
#include "ftp.h"
#include "http.h"
#include "ips.h"
#include "mails.h"
#include "tcp.h"
#include "telnet.h"
#include "udp.h"

long int counter;
int verbose = 1;

void headers(const struct pcap_pkthdr *header) {
    printf(YEL "Headers : ");
    time_t time = header->ts.tv_sec;
    char *time_str = ctime(&time);
    time_str[strlen(time_str) - 1] = '\0';
    printf("time : %s, ", time_str);
    if (verbose >= 2) {
        printf("caplen : %d, len : %d\n", header->caplen, header->len);
    }
    printf(reset);
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

    switch (ntohs(ether_type)) {
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
        printf(RED "Unknown Protocol :'(\n" reset);
    }

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
            printf(MAG "Unknown UDP service :'(\n" reset);
        }
        break;
    case 6:
        uint16_t tcp_psh;
        tcp(packet, &offset, &sport, &dport, &tcp_psh);
        if (sport == 21 || dport == 21 || sport == 20 || dport == 20) {
            ftp(packet, &offset, &sport, &dport, &tcp_psh, &length);
        } else if (sport == 25 || dport == 25) {
            smtp(packet, &offset, &tcp_psh, &length);
        } else if (sport == 22 || dport == 22) {
            printf(MAG "SSH :%s", sad);
            printf("\n" reset);
        } else if (sport == 23 || dport == 23) {
            telnet(packet, &offset, &tcp_psh, &length);
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
            printf(MAG "Unknown TCP service :'(\n" reset);
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
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf(RED "Usage: %s -i interface -f filter -o offline_file -v verbose\n" reset, argv[0]);
        return 1;
    }

    int c;
    char *interface = NULL;
    char *offline_file = NULL;
    char *filter = NULL;
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
        if (verbose >= 3) {
            printf("### Interfaces : ###\n");
            while (interfaces->next != NULL) {
                printf("- %s, \n", interfaces->name);
                interfaces = interfaces->next;
            }
        }
    }

    if (interface == NULL && offline_file == NULL) {
        printf("Error: interface or offline_file not specified\n");
        return 1;
    }

    pcap_t *capture;
    bpf_u_int32 mask;

    if (interface) {
        if (verbose >= 3) {
            bpf_u_int32 netaddr;
            if (pcap_lookupnet(interface, &netaddr, &mask, errbuf) == PCAP_ERROR) {
                printf("Error: %s", errbuf);
                return 1;
            }
            printf("\n%s : IP %s, ", interface, inet_ntoa(*(struct in_addr *)&netaddr));
            printf("masque %s\n\n", inet_ntoa(*(struct in_addr *)&mask));
        }

        if ((capture = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n             ### Capture on %s : ###\n\n", interface);
    }

    if (offline_file) {
        if ((capture = pcap_open_offline(offline_file, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n             ### Capture on %s : ###\n\n", offline_file); // centrer ??
    }

    if (filter) {
        struct bpf_program fp;
        if (pcap_compile(capture, &fp, filter, 0, mask) == PCAP_ERROR) {
            printf("Filter compile error: %s\n", errbuf);
            return 1;
        }
        if (pcap_setfilter(capture, &fp) == PCAP_ERROR) {
            printf("Filter setting error: %s\n", errbuf);
            return 1;
        }
        printf("Filter : ");
        printf(CYN "%s\n\n" reset, filter);
    }

    if (pcap_loop(capture, -1, got_packet, NULL) == PCAP_ERROR) {
        printf("Error: %s", errbuf);
        return 1;
    }

    return 0;
}