#include "packet_parsing.h"

void parse_packet(const u_char *packet){
    // Analyse de l'en-tête Ethernet
    struct ether_header *eth_header = (struct ether_header *) packet;
    parse_eth(eth_header);
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) // IPv4 case
    {
        parse_IPv4(packet);
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){ //IPv6 case
        parse_IPv6(packet);
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP || 
             ntohs(eth_header->ether_type) == ETHERTYPE_REVARP){ // ARP case 
        parse_ARP(packet);
    }
    else{
        printf(" ethertype not found ");
    }
    printf("\n-----\n");
}






void parse_protocol(u_char protocol, const u_char *packet){
    // we search wich protocol we have 
    switch (protocol) {
        case IPPROTO_TCP :// TCP
            parse_tcp(packet);
            break;
        case IPPROTO_UDP: // UDP
            //parse_udp(packet);
            break;
        case IPPROTO_ICMP: //IMCP
            //parse_icmp(packet);
            break;
        case IPPROTO_ICMPV6: //ICMPv6
            //parse_icmpv6(packet);
    }
}