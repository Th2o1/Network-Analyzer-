#include "link_layer.h"

void parse_IPv4(struct ip *ip_header, int verbosity){
    if (verbosity >= 1) {
        printf("IPv4 Packet from %s to %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));
    }
    if (verbosity >= 2) {
        printf("TTL: %d, Protocol: %d\n", ip_header->ip_ttl, ip_header->ip_p);
    }

    /*
    printf("Version : %d\n", ip_header->ip_v);
    printf("Longueur de l'en-tête : %d octets\n", ip_header->ip_hl * 4);
    printf("Type de service : %d\n", ip_header->ip_tos);
    printf("Longueur totale : %d\n", ntohs(ip_header->ip_len));
    printf("Identification : %d\n", ntohs(ip_header->ip_id));
    printf("TTL : %d\n", ip_header->ip_ttl);
    printf("Protocole : %d\n", ip_header->ip_p);
    printf("Checksum : %d\n", ntohs(ip_header->ip_sum));
    printf("Adresse source : %s\n", inet_ntoa(ip_header->ip_src));
    printf("Adresse de destination : %s\n", inet_ntoa(ip_header->ip_dst));
    */
}



void parse_packet(const u_char *packet, int* verb){
    // Analyse de l'en-tête Ethernet
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) // IPv4 case
    {
        printf("IPv4\n");
        parse_IPv4(ip_header, *verb);
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){ //IPv6 case
        printf("ipv6\n");
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){ // ARP case 
        printf("ARP\n");
    }
}