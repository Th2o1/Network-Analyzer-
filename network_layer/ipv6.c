#include "ipv6.h"

void parse_IPv6(const u_char *packet){
    // Move the pointer to the IPv6 header
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

    printf("IPv6 (");

    // Extract src and dst
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_addr, sizeof(src_addr));
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_addr, sizeof(dst_addr));

    // Printing in packet order
    printf("Priority %u ", ipv6_header->ip6_vfc);
    printf("Next Header %u ",ipv6_header->ip6_nxt);
    printf("Flow Label %u ", ipv6_header->ip6_flow);
    printf("Payload length %u ",ipv6_header->ip6_plen);
    printf("Hops Limits %u ",ipv6_header->ip6_hlim);
    printf("Source %s ", src_addr);
    printf("Destination %s ", dst_addr);

    printf(") ");

    parse_protocol(ipv6_header->ip6_nxt, packet+40);

}