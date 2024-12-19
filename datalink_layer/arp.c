#include "arp.h"

void print_ip_address(u_char *address){
    for(int i = 0; i < 4; i++){ 
        printf("%d", address[i]); 
        if(i!=3){printf(".");}
    }
    printf(" ");
}

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
        printf("REVERSE REQUEST ");
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
            printf("IPv4 ");
            break;
        case 0x86DD: // IPv6
            printf("IPv6 ");
            break;
        case 0x0806: // ARP 
            printf("ARP ");
            break;
        case 0x8035: // RARP
            printf("Reverse ARP (RARP) ");
            break;
        case 0x88CC: // LLDP
            printf("Link Layer Discovery Protocol (LLDP) ");
            break;
        case 0x8100: // VLAN Tagging (802.1Q)
            printf("VLAN Tagging (802.1Q) ");
            break;
        case 0x8847: // MPLS Unicast
            printf("MPLS (Unicast) ");
            break;
        case 0x8848: // MPLS Multicast
            printf("MPLS (Multicast) ");
            break;
        default:
            printf("Unknown or custom protocol format ");
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
        default:
            printf("Unknown or custom hardware format ");
            break;
    }
}

void parse_ARP(const u_char *packet){
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    printf("ARP ");
    print_hardware_format(ntohs(arp_header->arp_hrd));
    print_ARP_protocol_format(ntohs(arp_header->arp_pro));

    parse_ARP_operation(ntohs(arp_header->arp_op)); //ntohs for conversion little / big endian if necessary
    printf("Target: MAC: ");
    print_ether_address(arp_header->arp_tha); // Target MAC address
    printf("IP: ");
    print_ip_address(arp_header->arp_tpa); // Target IP address

    printf("Sender: MAC: ");
    print_ether_address(arp_header->arp_sha); // Sender MAC address
    printf("IP: ");
    print_ip_address(arp_header->arp_spa); // Sender IP address

    printf("Size of MAC address %d", arp_header->arp_hln);


}




