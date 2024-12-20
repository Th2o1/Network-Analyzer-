#include "icmpv6.h"
void print_na_flags(uint32_t flags) {
    printf("Flags [");
    if (flags & ND_NA_FLAG_SOLICITED)
        printf("solicited");
    if (flags & ND_NA_FLAG_OVERRIDE)
        printf(", override");
    if (flags & ND_NA_FLAG_ROUTER)
        printf(", router");
    printf("]");
}

// Function to handle ICMPv6 messages based on type
void handle_icmpv6_message(const struct icmp6_hdr *icmpv6_header, const u_char *packet, size_t header_size) {
    switch (icmpv6_header->icmp6_type) {
        case ND_NEIGHBOR_SOLICIT: {
            const struct nd_neighbor_solicit *ns_header = 
                (const struct nd_neighbor_solicit *)(packet + header_size);
            char target_addr[INET6_ADDRSTRLEN];

            printf("neighbor solicitation, length %zu, who as %s, ",
                   sizeof(struct nd_neighbor_solicit),
                   inet_ntop(AF_INET6, &ns_header->nd_ns_target, target_addr, INET6_ADDRSTRLEN));
            break;
        }
        case ND_NEIGHBOR_ADVERT: {
            const struct nd_neighbor_advert *na_header = 
                (const struct nd_neighbor_advert *)(packet + header_size);
            char target_addr[INET6_ADDRSTRLEN];

            printf("neighbor advertisement, length %zu, tgt is %s, ",
                   sizeof(struct nd_neighbor_advert),
                   inet_ntop(AF_INET6, &na_header->nd_na_target, target_addr, INET6_ADDRSTRLEN));
            if(verbosity >= MEDIUM) print_na_flags(na_header->nd_na_flags_reserved);
            printf("\n");
            break;
        }
        case ICMP6_ECHO_REQUEST:
            printf("echo request, length %zu, ",
                   sizeof(struct icmp6_hdr));
            break;
        case ICMP6_ECHO_REPLY:
            printf("echo reply, length %zu, ",
                   sizeof(struct icmp6_hdr));
            break;
        case ICMP6_DST_UNREACH:
            printf("destination unreachable, length %zu, ",
                   sizeof(struct icmp6_hdr));
            break;
        case ICMP6_TIME_EXCEEDED:
            printf("time exceeded, length %zu, ",
                   sizeof(struct icmp6_hdr));
            break;
        default:
            printf("unknown type %u, length %zu, ",
                   icmpv6_header->icmp6_type,
                   sizeof(struct icmp6_hdr));
            break;
    }
}

// Main function to parse and display ICMPv6 header information
void parse_icmpv6(const u_char *packet, size_t header_size) {
    const struct icmp6_hdr *icmpv6_header = (const struct icmp6_hdr *)(packet + header_size);
    printf("ICMPv6: ");
    if(verbosity >= MEDIUM) printf("Checksum: 0x%04x; ", ntohs(icmpv6_header->icmp6_cksum));
    // Call the handler based on the message type
    handle_icmpv6_message(icmpv6_header, packet, header_size);
}