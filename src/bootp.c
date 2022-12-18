#include "bootp.h"

extern int verbose;

char *dhcp_type(uint8_t type) {
    switch (type) {
    case 1:
        return "DHCP_DISCOVER";
    case 2:
        return "DHCP_OFFER";
    case 3:
        return "DHCP_REQUEST";
    case 4:
        return "DHCP_DECLINE";
    case 5:
        return "DHCP_ACK";
    case 6:
        return "DHCP_NAK";
    case 7:
        return "DHCP_RELEASE";
    case 8:
        return "DHCP_INFORM";
    default:
        return "UNKNOWN";
    }
}

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
        if (bootp->bp_sname[0])
            printf("sname : %s, ", bootp->bp_sname);
        else
            printf("sname : not given, ");
        if (bootp->bp_file[0])
            printf("file : %s, ", bootp->bp_file);
        else
            printf("file : not given, ");
        printf("\n");
    }

    /* BOOTP options */
    if (bootp->bp_vend[0] == 99 && bootp->bp_vend[1] == 130 && bootp->bp_vend[2] == 83 && bootp->bp_vend[3] == 99) { // Magic cookie
        *offset += 4;
        printf("DHCP : ");
        while (packet[*offset] != 0xff) {
            uint8_t type = packet[*offset];
            (*offset)++;
            uint8_t len = packet[*offset];
            (*offset)++;
            if (verbose >= 2 && type == 53) {
                printf("%s, ", dhcp_type(packet[*offset]));
            }
            if (verbose >= 3) {
                /* /!\ The options were generated with a coding assistant /!\ */
                switch (type) {
                case 1:
                    printf("subnet mask : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 3:
                    printf("router : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 6:
                    printf("DNS : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 12:
                    printf("host name : %s, ", &packet[*offset]);
                    break;
                case 15:
                    printf("domain : %s, ", &packet[*offset]);
                    break;
                case 17:
                    printf("root path : %s, ", &packet[*offset]);
                    break;
                case 28:
                    printf("broadcast address : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 33:
                    printf("static route : %s, ", &packet[*offset]);
                    break;
                case 42:
                    printf("NTP : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 43:
                    printf("vendor : %s, ", &packet[*offset]);
                    break;
                case 44:
                    printf("subnet mask : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 46:
                    printf("MTU : %d, ", *(uint16_t *)&packet[*offset]);
                    break;
                case 47:
                    printf("path MTU : %s, ", &packet[*offset]);
                    break;
                case 50:
                    printf("requested IP : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 51:
                    printf("lease time : %us, ", *(uint32_t *)&packet[*offset]);
                    break;
                case 52:
                    printf("option overload : %d, ", packet[*offset]);
                    break;
                case 53:
                    break; // already printed
                case 54:
                    printf("server identifier : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 55:
                    printf("parameter request list : ");
                    for (int i = 0; i < len; i++) {
                        printf("%d ", packet[*offset + i]);
                    }
                    printf(", ");
                    break;
                case 56:
                    printf("message : %s, ", &packet[*offset]);
                    break;
                case 57:
                    printf("max message size : %d, ", *(uint16_t *)&packet[*offset]);
                    break;
                case 58:
                    printf("renewal time : %u, ", *(uint32_t *)&packet[*offset]);
                    break;
                case 59:
                    printf("rebinding time : %u, ", *(uint32_t *)&packet[*offset]);
                    break;
                case 60:
                    printf("vendor class identifier : %s, ", &packet[*offset]);
                    break;
                case 61:
                    printf("client identifier : %s, ", &packet[*offset + 1]);
                    break;
                case 64:
                    printf("NIS domain : %s, ", &packet[*offset]);
                    break;
                case 65:
                    printf("NIS servers : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 66:
                    printf("TFTP server name : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset]));
                    break;
                case 67:
                    printf("boot file name : %s, ", &packet[*offset]);
                    break;
                case 68:
                    printf("mobile IP home agent : %s, ", &packet[*offset]);
                    break;
                case 69:
                    printf("SMTP server : %s, ", &packet[*offset]);
                    break;
                case 70:
                    printf("POP3 server : %s, ", &packet[*offset]);
                    break;
                case 71:
                    printf("NNTP server : %s, ", &packet[*offset]);
                    break;
                case 72:
                    printf("WWW server : %s, ", &packet[*offset]);
                    break;
                case 73:
                    printf("Finger server : %s, ", &packet[*offset]);
                    break;
                case 74:
                    printf("IRC server : %s, ", &packet[*offset]);
                    break;
                case 75:
                    printf("StreetTalk server : %s, ", &packet[*offset]);
                    break;
                case 76:
                    printf("STDAS server : %s, ", &packet[*offset]);
                    break;
                case 77:
                    printf("user class : %s, ", &packet[*offset]);
                    break;
                case 78:
                    printf("directory agent : %s, ", &packet[*offset]);
                    break;
                case 79:
                    printf("service scope : %s, ", &packet[*offset]);
                    break;
                case 80:
                    printf("Rapid Commit : %s, ", &packet[*offset]);
                    break;
                case 81:
                    printf("client FQDN : %s, ", &packet[*offset]);
                    break;
                case 82:
                    printf("relay agent information : ");
                    for (int i = 3; i < len; i++) {
                        printf("%c", packet[*offset + i]);
                    }
                    printf(", ");
                    break;
                case 83:
                    printf("iSNS : %s, ", &packet[*offset]);
                    break;
                case 84:
                    printf("NDSS servers : %s, ", &packet[*offset]);
                    break;
                case 85:
                    printf("NDSS tree name : %s, ", &packet[*offset]);
                    break;
                case 86:
                    printf("NDS context : %s, ", &packet[*offset]);
                    break;
                case 87:
                    printf("BCMCS controller domain name list : %s, ", &packet[*offset]);
                    break;
                case 88:
                    printf("BCMCS controller IPv4 address option : %s, ", &packet[*offset]);
                    break;
                case 89:
                    printf("FQDN options : %s, ", &packet[*offset]);
                    break;
                case 90:
                    printf("authentication : %s, ", &packet[*offset]);
                    break;
                case 91:
                    printf("associated IP : %s, ", &packet[*offset]);
                    break;
                case 92:
                    printf("client system : %s, ", &packet[*offset]);
                    break;
                case 93:
                    printf("client NDI : %s, ", &packet[*offset]);
                    break;
                case 94:
                    printf("LDAP : %s, ", &packet[*offset]);
                    break;
                case 95:
                    printf("UUID/GUID : %s, ", &packet[*offset]);
                    break;
                case 96:
                    printf("user auth : %s, ", &packet[*offset]);
                    break;
                case 97:
                    printf("GeoConf CIVIC : %s, ", &packet[*offset]);
                    break;
                case 98:
                    printf("PCode : %s, ", &packet[*offset]);
                    break;
                case 99:
                    printf("TCode : %s, ", &packet[*offset]);
                    break;
                case 100:
                    printf("NetInfo parent server address : %s, ", &packet[*offset]);
                    break;
                case 101:
                    printf("NetInfo parent server tag : %s, ", &packet[*offset]);
                    break;
                case 102:
                    printf("URL : %s, ", &packet[*offset]);
                    break;
                case 103:
                    printf("auto-configure : %s, ", &packet[*offset]);
                    break;
                case 104:
                    printf("name service search : %s, ", &packet[*offset]);
                    break;
                case 105:
                    printf("subnet selection : %s, ", &packet[*offset]);
                    break;
                case 106:
                    printf("DNS domain search list : %s, ", &packet[*offset]);
                    break;
                case 107:
                    printf("SIPS server : %s, ", &packet[*offset]);
                    break;
                case 108:
                    printf("classless static route : %s, ", &packet[*offset]);
                    break;
                case 109:
                    printf("CCC : %s, ", &packet[*offset]);
                    break;
                case 110:
                    printf("GeoConf : %s, ", &packet[*offset]);
                    break;
                case 111:
                    printf("V-I Vendor class : %s, ", &packet[*offset]);
                    break;
                case 112:
                    printf("V-I Vendor specific information : %s, ", &packet[*offset]);
                    break;
                case 113:
                    printf("TFTP server address : %s, ", &packet[*offset]);
                    break;
                case 114:
                    printf("status code : %s, ", &packet[*offset]);
                    break;
                case 115:
                    printf("base time : %s, ", &packet[*offset]);
                    break;
                case 116:
                    printf("start time of state : %s, ", &packet[*offset]);
                    break;
                case 117:
                    printf("query start time : %s, ", &packet[*offset]);
                    break;
                case 118:
                    printf("query end time : %s, ", &packet[*offset]);
                    break;
                case 119:
                    printf("domain search : %s, ", &packet[*offset]);
                    break;
                case 120:
                    printf("SIP server : %s, ", inet_ntoa(*(struct in_addr *)&packet[*offset + 1]));
                    break;
                case 121:
                    printf("classless static route : %s, ", &packet[*offset]);
                    break;
                case 122:
                    printf("vendor class : %s, ", &packet[*offset]);
                    break;
                case 123:
                    printf("vendor specific information : %s, ", &packet[*offset]);
                    break;
                case 124:
                    printf("TFTP server address : %s, ", &packet[*offset]);
                    break;
                case 125:
                    printf("status code : %s, ", &packet[*offset]);
                    break;
                case 126:
                    printf("base time : %s, ", &packet[*offset]);
                    break;
                case 127:
                    printf("start time of state : %s, ", &packet[*offset]);
                    break;
                case 128:
                    printf("query start time : %s, ", &packet[*offset]);
                    break;
                case 129:
                    printf("query end time : %s, ", &packet[*offset]);
                    break;
                case 255:
                    printf("end");
                    break;
                default:
                    printf("type : %d, ", type);
                    break;
                }
            }
            *offset += len;
        }
        printf("end");
    }
    printf(reset "\n");
}