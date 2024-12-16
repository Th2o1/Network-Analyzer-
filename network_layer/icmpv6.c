#include "icmpv6.h"
#include <stdio.h>
#include <netinet/in.h>

// Function to print the ICMPv6 message type and code
void print_icmpv6_message(const struct icmp6_hdr *icmpv6_header) {
    switch (icmpv6_header->icmp6_type) {
        case ND_NEIGHBOR_SOLICIT:
            printf("Message: Neighbor Solicitation");
            break;
        case ND_NEIGHBOR_ADVERT:
            printf("Message: Neighbor Advertisement");
            break;
        case ICMP6_ECHO_REQUEST:
            printf("Message: Echo Request");
            break;
        case ICMP6_ECHO_REPLY:
            printf("Message: Echo Reply");
            break;
        case ICMP6_DST_UNREACH:
            printf("Message: Destination Unreachable");
            break;
        case ICMP6_TIME_EXCEEDED:
            printf("Message: Time Exceeded");
            break;
        default:
            printf("Message: Other ICMPv6 Type");
            break;
    }
    printf("\n");
}

// Function to parse and display ICMPv6 header information
void parse_icmpv6(const u_char *packet, size_t header_size) {
    const struct icmp6_hdr *icmpv6_header = (const struct icmp6_hdr *)(packet + header_size);

    printf("ICMPv6 Header:\n");
    printf("Type: %u\n", icmpv6_header->icmp6_type);
    printf("Code: %u\n", icmpv6_header->icmp6_code);
    printf("Checksum: 0x%04x\n", ntohs(icmpv6_header->icmp6_cksum));

    // Call the function to print the ICMPv6 message details
    print_icmpv6_message(icmpv6_header);
}