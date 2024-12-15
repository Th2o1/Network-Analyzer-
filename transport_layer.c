#include "transport_layer.h"



void parse_udp(const u_char *packet){
    struct udphdr *udp_header = (struct udphdr *)packet;
    printf("UDP: ");
    printf("Source Port: %u, Destination Port: %u ", ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport));
    printf("length : %u ", ntohs(udp_header->uh_ulen));

    // TODO: detect BOOTP and DHCP

    return; 
}
void parse_icmp(const u_char *packet){
    const struct icmp *icmp_header = (const struct icmp *)packet;

    printf("ICMP: ");
    printf("Type: %u ", icmp_header->icmp_type);
    printf("Code: %u ", icmp_header->icmp_code);
    printf("Checksum: 0x%04x ", ntohs(icmp_header->icmp_cksum));

    switch (icmp_header->icmp_type) {
        case ICMP_ECHOREPLY:
            printf("Message: Echo Reply ");
            printf("ID: %u, Sequence: %u", 
                ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));
            break;
        case ICMP_ECHO:
            printf("Message: Echo Request ");
            printf("ID: %u, Sequence: %u ", 
                ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));
            break;
        case ICMP_UNREACH:
            printf("Message: Destination Unreachable ");
            printf("Code Explanation: ");
            switch (icmp_header->icmp_code) {
                case ICMP_UNREACH_NET:
                    printf("Network Unreachable ");
                    break;
                case ICMP_UNREACH_HOST:
                    printf("Host Unreachable ");
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    printf("Protocol Unreachable ");
                    break;
                case ICMP_UNREACH_PORT:
                    printf("Port Unreachable ");
                    break;
                default:
                    printf("Unknown code %u ", icmp_header->icmp_code);
                    break;
            }
            break;
        case ICMP_TIMXCEED:
            printf("Message: Time Exceeded  ");
            printf("Code Explanation: ");
            if (icmp_header->icmp_code == ICMP_TIMXCEED_INTRANS)
                printf("TTL Expired in Transit ");
            else if (icmp_header->icmp_code == ICMP_TIMXCEED_REASS)
                printf("Fragment Reassembly Time Exceeded ");
            else
                printf("Unknown code %u ", icmp_header->icmp_code);
            break;
        default:
            printf("Message: Other ICMP Type ");
            break;
    }
}
void parse_icmpv6(const u_char *packet){
    const struct icmp6_hdr *icmpv6_header = (const struct icmp6_hdr *)packet;

    printf("ICMPv6 Header: ");
    printf("- Type: %u ", icmpv6_header->icmp6_type);
    printf("- Code: %u ", icmpv6_header->icmp6_code);
    printf("- Checksum: 0x%04x ", ntohs(icmpv6_header->icmp6_cksum));

    switch (icmpv6_header->icmp6_type) {
        case ND_NEIGHBOR_SOLICIT:
            printf("Message: Neighbor Solicitation ");
            break;
        case ND_NEIGHBOR_ADVERT:
            printf("Message: Neighbor Advertisement ");
            break;
        case ICMP6_ECHO_REQUEST:
            printf("Message: Echo Request ");
            break;
        case ICMP6_ECHO_REPLY:
            printf("Message: Echo Reply ");
            break;
        case ICMP6_DST_UNREACH:
            printf("Message: Destination Unreachable ");
            break;
        case ICMP6_TIME_EXCEEDED:
            printf("Message: Time Exceeded ");
            break;
        default:
            printf("Message: Other ICMPv6 Type ");
            break;
    }
} 


void parse_protocol(u_char protocol, const u_char *packet){
    // we search wich protocol we have 
    switch (protocol) {
        case IPPROTO_TCP :// TCP
            parse_tcp(packet);
            break;
        case IPPROTO_UDP: // UDP
            parse_udp(packet);
            break;
        case IPPROTO_ICMP: //IMCP
            parse_icmp(packet);
            break;
        case IPPROTO_ICMPV6: //ICMPv6
            parse_icmpv6(packet);
    }
}