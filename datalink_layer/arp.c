#include "arp.h"

void print_ip_address(u_char *address){
    for(int i = 0; i < 4; i++){ 
        printf("%d", address[i]); 
        if(i!=3){printf(".");}
    }
    printf(" ");
}

void parse_ARP_operation(u_short ar_op, const struct ether_arp *arp_header) {
    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    char sender_mac[18], target_mac[18];

    // Convert IP addresses to strings
    inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

    // Convert MAC addresses to strings
    snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
             arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);

    snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
             arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);

    switch (ar_op) {
        case ARPOP_REQUEST:
            printf("Request who-has %s tell %s, length %lu\n",
                   target_ip, sender_ip, sizeof(struct ether_arp));
            break;
        case ARPOP_REPLY:
            printf("Reply %s is-at %s, length %lu\n",
                   sender_ip, sender_mac, sizeof(struct ether_arp));
            break;
        case ARPOP_REVREQUEST:
            printf("Reverse Request who-is %s tell %s, length %lu\n",
                   target_mac, sender_mac, sizeof(struct ether_arp));
            break;
        case ARPOP_REVREPLY:
            printf("Reverse Reply %s at %s, length %lu\n",
                   sender_mac, sender_ip, sizeof(struct ether_arp));
            break;
        case ARPOP_INVREQUEST:
            printf("Inverse Request who-has %s tell %s, length %lu\n",
                   target_mac, sender_mac, sizeof(struct ether_arp));
            break;
        case ARPOP_INVREPLY:
            printf("Inverse Reply %s is-at %s, length %lu\n",
                   sender_mac, sender_ip, sizeof(struct ether_arp));
            break;
        default:
            printf("Unknown ARP operation, length %lu\n", sizeof(struct ether_arp));
            break;
    }
}

void print_ARP_protocol_format(u_short ar_pro) {
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
            printf("RARP ");
            break;
        case 0x88CC: // LLDP
            printf("LLDP ");
            break;
        case 0x8100: // VLAN Tagging (802.1Q)
            printf("VLAN Tagging");
            break;
        case 0x8847: // MPLS Unicast
            printf("MPLS (Unicast) ");
            break;
        case 0x8848: // MPLS Multicast
            printf("MPLS (Multicast) ");
            break;
        default:
            printf("Unknown ");
            break;
    }
    if(verbosity == HIGH) printf("- 0x%04x ", ar_pro);
}
void print_hardware_format(u_short ar_hrd) {
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
            printf("IEEE 1394 ");
            break;
        default:
            printf("Unknown ");
            break;
    }
    if(verbosity == HIGH) printf("- 0x%04x ", ar_hrd);
}

void parse_ARP(const u_char *packet){
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    printf("ARP ");
    print_hardware_format(ntohs(arp_header->arp_hrd));
    printf("(len %u), ",arp_header->arp_hln );
    print_ARP_protocol_format(ntohs(arp_header->arp_pro));
    printf("(len %u), ",arp_header->arp_pln );

    parse_ARP_operation(ntohs(arp_header->arp_op), arp_header); //ntohs for conversion little / big endian if necessary


}




