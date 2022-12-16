#include "telnet.h"

extern int verbose;

void telnet(const u_char *packet, int *offset, uint16_t *tcp_psh, uint16_t *length) {
    printf(MAG "Telnet : ");
    if (*tcp_psh && verbose >= 2) {
        for (;;) {
            if (packet[*offset] == 0xff) { // Control sequence
                printf("IAC ");
                (*offset)++;
                if (*offset >= *length)
                    break;
                switch (packet[*offset]) {
                case 0xf0:
                    printf("SE ");
                    break;
                case 0xf1:
                    printf("NOP ");
                    break;
                case 0xf2:
                    printf("DMARK ");
                    break;
                case 0xf3:
                    printf("BRK ");
                    break;
                case 0xf4:
                    printf("IP ");
                    break;
                case 0xf5:
                    printf("AO ");
                    break;
                case 0xf6:
                    printf("AYT ");
                    break;
                case 0xf7:
                    printf("EC ");
                    break;
                case 0xf8:
                    printf("EL ");
                    break;
                case 0xf9:
                    printf("GA ");
                    break;
                case 0xfa:
                    printf("SB ");
                    break;
                case 0xfb:
                    printf("WILL ");
                    break;
                case 0xfc:
                    printf("WONT ");
                    break;
                case 0xfd:
                    printf("DO ");
                    break;
                case 0xfe:
                    printf("DONT ");
                    break;
                case 0xff:
                    printf("IAC ");
                    break;
                default:
                    printf("UNKNOWN ");
                    break;
                }
                (*offset)++;
                if (*offset >= *length)
                    break;
                switch (packet[*offset]) {
                case 0x00:
                    printf("BINARY ");
                    break;
                case 0x01:
                    printf("ECHO ");
                    break;
                case 0x02:
                    printf("RCP ");
                    break;
                case 0x03:
                    printf("SGA ");
                    break;
                case 0x04:
                    printf("NAMS ");
                    break;
                case 0x05:
                    printf("STATUS ");
                    break;
                case 0x06:
                    printf("TM ");
                    break;
                case 0x07:
                    printf("RCTE ");
                    break;
                case 0x08:
                    printf("NAOL ");
                    break;
                case 0x09:
                    printf("NAOP ");
                    break;
                case 0x0a:
                    printf("NAOCRD ");
                    break;
                case 0x0b:
                    printf("NAOHTS ");
                }
                (*offset)++;
            } else {
                printf(isprint(packet[*offset]) || packet[*offset] == '\n' ? "%c" : ".", packet[*offset]);
                (*offset)++;
                if (*offset >= *length)
                    break;
            }
        }
    }
    printf("\n" reset);
}