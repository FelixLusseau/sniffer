#ifndef ANALYSEUR_H
#define ANALYSEUR_H

#include <ctype.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define YEL "\e[0;33m"
#define BLU "\e[0;34m"
#define MAG "\e[0;35m"
#define CYN "\e[0;36m"
#define reset "\e[0m"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * @brief Function to print the headers of the packet
 *
 * @param header
 */
void headers(const struct pcap_pkthdr *header);

/**
 * @brief Function that analyses the packet
 *
 * @param args
 * @param header
 * @param packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif