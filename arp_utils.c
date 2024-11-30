#include "arp_utils.h"


void parse_ARP_operation(u_short ar_op){
    switch (ar_op)
    {
    case ARPOP_REQUEST:
        printf("REQUEST ");
        break;
    case ARPOP_REPLY:
        printf("RESPONSE ");
        break;
    case ARPOP_REVREQUEST:
        printf("REVERSE REQUEST");
        break;
    case ARPOP_REVREPLY:
        printf("REVERSE REPLY ");
        break;
    case ARPOP_INVREQUEST:
        printf("INVERSE REQUEST ");
        break;
    case ARPOP_INVREPLY:
        printf("INVERSE REPLY ");
        break;
    default:
        break;
    }
}

void print_ARP_protocol_format(u_short ar_pro) {
    printf("Protocol address format : 0x%04x - ", ar_pro);
    switch (ar_pro) {
        case 0x0800: // IPv4
            printf("IPv4\n");
            break;
        case 0x86DD: // IPv6
            printf("IPv6\n");
            break;
        case 0x0806: // ARP 
            printf("ARP\n");
            break;
        case 0x8035: // RARP
            printf("Reverse ARP (RARP)\n");
            break;
        case 0x88CC: // LLDP
            printf("Link Layer Discovery Protocol (LLDP)\n");
            break;
        case 0x8100: // VLAN Tagging (802.1Q)
            printf("VLAN Tagging (802.1Q)\n");
            break;
        case 0x8847: // MPLS Unicast
            printf("MPLS (Unicast)\n");
            break;
        case 0x8848: // MPLS Multicast
            printf("MPLS (Multicast)\n");
            break;
        default:
            printf("Unknown or custom protocol format\n");
            break;
    }
}
void print_hardware_format(u_short ar_hrd) {
    printf("Hardware address format: 0x%04x - ", ar_hrd);
    switch (ar_hrd) {
        case ARPHRD_ETHER: // Ethernet
            printf("Ethernet ");
            break;
        case ARPHRD_IEEE802: // Token-ring
            printf("Token-ring ");
            break;
        case ARPHRD_FRELAY: // Frame relay
            printf("Frame Relay ");
            break;
        case ARPHRD_IEEE1394: // IEEE 1394 (FireWire)
            printf("IEEE 1394 (FireWire) ");
            break;
        case ARPHRD_IEEE1394_EUI64: // IEEE 1394 EUI-64
            printf("IEEE 1394 EUI-64 ");
            break;
        default:
            printf("Unknown or custom hardware format ");
            break;
    }
}