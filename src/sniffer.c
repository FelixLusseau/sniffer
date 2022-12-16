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
    (void)args;
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

    /* Switch for the header under the ethernet one */
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
        printf(RED "RARP : \n" reset);
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

    /* Switch for the header under the IP one */
    switch (protocol) {
    case IPPROTO_ICMP:
        printf(BLU "ICMP ");
        printf("\n" reset);
        break;
    case IPPROTO_UDP:
        udp(packet, &offset, &sport, &dport);

        /* Analyse of the ports to find the application */
        if (sport == 67 || sport == 68 || dport == 67 || dport == 68) {
            bootp_dhcp(packet, &offset);
        } else if (sport == 53 || dport == 53) {
            printf(MAG "DNS : ");
            dns(packet, &offset);
        } else if (sport == 443 || dport == 443) {
            printf(MAG "HTTP/3 QUIC :%s\n" reset, sad);
        } else {
            printf(MAG "Unknown UDP service :'(\n" reset);
        }
        break;
    case IPPROTO_TCP:
        uint16_t tcp_psh;
        tcp(packet, &offset, &sport, &dport, &tcp_psh);

        /* Analyse of the ports to find the application */
        if (sport == 21 || dport == 21 || sport == 20 || dport == 20) {
            ftp(packet, &offset, &sport, &dport, &tcp_psh, &length);
        } else if (sport == 25 || dport == 25) {
            smtp(packet, &offset, &tcp_psh, &length);
        } else if (sport == 22 || dport == 22) {
            printf(MAG "SSH :%s", sad);
            printf("\n" reset);
        } else if (sport == 23 || dport == 23) {
            telnet(packet, &offset, &tcp_psh, &length);
        } else if (sport == 53 || dport == 53) {
            uint16_t length = ntohs(*(uint16_t *)(packet + offset));
            offset += 2;
            printf(MAG "TCP DNS : %d bytes\n", length);
            if (tcp_psh) {
                dns(packet, &offset);
            }
            printf(reset);
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
    case IPPROTO_ICMPV6:
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
    /* Verify the number of arguments given */
    if (argc < 4) { // -vx == -v x
        printf(RED "Usage: %s (-i interface | -o offline_file) -v verbose [-f filter]\n" reset, argv[0]);
        return 1;
    }

    int c;
    char *interface = NULL;
    char *offline_file = NULL;
    char *filter = NULL;
    /* Extracting the arguments from the command line */
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
            printf(RED "Usage: %s (-i interface | -o offline_file) -v verbose [-f filter]\n" reset, argv[0]);
            return 1;
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    /* Scanning the internet interfaces of the system */
    if (verbose >= 3) {
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
            /* Research for the interface IP address and netmask */
            if (pcap_lookupnet(interface, &netaddr, &mask, errbuf) == PCAP_ERROR) {
                printf("Error: %s", errbuf);
                return 1;
            }
            printf("\n%s : IP %s, ", interface, inet_ntoa(*(struct in_addr *)&netaddr));
            printf("masque %s\n\n", inet_ntoa(*(struct in_addr *)&mask));
        }

        /* Opening the interface for the capture */
        if ((capture = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n             ### Capture on %s : ###\n\n", interface);
    }

    if (offline_file) {
        /* Opening the capture file for the capture */
        if ((capture = pcap_open_offline(offline_file, errbuf)) == NULL) {
            printf("Error: %s", errbuf);
            return 1;
        }
        printf("\n             ### Capture on %s : ###\n\n", offline_file);
    }

    /* Compiling and setting the filter */
    if (filter) {
        struct bpf_program fp;
        if (pcap_compile(capture, &fp, filter, 0, mask) == PCAP_ERROR) {
            pcap_perror(capture, filter);
            return 1;
        }
        if (pcap_setfilter(capture, &fp) == PCAP_ERROR) {
            printf("Filter setting error: %s\n", errbuf);
            return 1;
        }
        printf("Filter : ");
        printf(CYN "%s\n\n" reset, filter);
    }

    /* Capture in loop and call the got_packet callback function to analyse the packet captured */
    if (pcap_loop(capture, -1, got_packet, NULL) == PCAP_ERROR) {
        printf("Error: %s", errbuf);
        return 1;
    }

    /* Close the capture if there is no CTRL+C to interrupt it */
    pcap_close(capture);

    return 0;
}