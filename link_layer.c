#include "link_layer.h"

void print_ether_address(const u_char* addr) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", addr[i]); // Display octet
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf(" ");
}
void print_ip_address(u_char *address){
    for(int i = 0; i < 4; i++){ 
        printf("%d", address[i]); 
        if(i!=3){printf(".");}
    }
}

void parse_IPv6(const u_char *packet){
    // Move the pointer to the IPv6 header
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
    // Extract IPv6 base fields
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_addr, sizeof(src_addr));
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_addr, sizeof(dst_addr));
    
    printf("IPv6 Packet from %s ", src_addr);
    printf("to %s ", dst_addr);

    printf("Payload length %u ",ipv6_header->ip6_plen);
    printf("Hops Limits %u ",ipv6_header->ip6_hlim);
    printf("Next Header %u ",ipv6_header->ip6_nxt);
    parse_protocol(ipv6_header->ip6_nxt, packet+40);

}

void parse_ARP_type(u_short ar_op){
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

void parse_ARP(const u_char *packet){
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    
    printf("ARP ");
    parse_ARP_type(ntohs(arp_header->arp_op)); //ntohs for conversion little / big endian if necessary
    
    printf("Target: MAC: ");
    print_ether_address(arp_header->arp_tha); // Target MAC address
    printf("IP: ");
    print_ip_address(arp_header->arp_tpa); // Target IP address

    printf(" Sender: MAC: ");
    print_ether_address(arp_header->arp_sha); // Sender MAC address
    printf("IP: ");
    print_ip_address(arp_header->arp_spa); // Sender IP address

}

void parse_IPv4(const u_char *packet){
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    if (verbosity >= LOW) {

        printf("IPv4 Packet from %s ", inet_ntoa(ip_header->ip_src));
        printf("to %s ", inet_ntoa(ip_header->ip_dst));
    }
    if (verbosity >= MEDIUM) {
        char* protocol = ip_header->ip_p == 6 ? "TCP" : "UDP"; //TCP has value 6 and UDP has value 17
        printf("TTL: %d, Protocol: %s ", ip_header->ip_ttl, protocol); 
    }

    parse_protocol(ip_header->ip_p, packet + (ip_header->ip_hl *4) + sizeof(struct ether_header));
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

void parse_eth(struct ether_header *eth_header){
    print_ether_address(eth_header->ether_dhost);
    printf("> ");
    print_ether_address(eth_header->ether_shost);
}

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
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){ // ARP case 
        parse_ARP(packet);
    }
    printf("\n-----\n");
}