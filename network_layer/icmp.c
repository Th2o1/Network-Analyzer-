#include "icmp.h"

// Function to handle the ICMP type
void handle_icmp_type(const struct icmp *icmp_header) {
    printf("Message: ");
    switch (icmp_header->icmp_type) {
        case ICMP_ECHOREPLY:
            printf("Echo Reply, ");
            printf("id: %u, Sequence: %u, ", 
                ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));
            break;
        case ICMP_ECHO:
            printf("Echo Request, ");
            printf("id: %u, Sequence: %u, ", 
                ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_seq));
            break;
        case ICMP_UNREACH:
            printf("Destination Unreachable: ");
            switch (icmp_header->icmp_code) {
                case ICMP_UNREACH_NET:
                    printf("Network Unreachable, ");
                    break;
                case ICMP_UNREACH_HOST:
                    printf("Host Unreachable, ");
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    printf("Protocol Unreachable, ");
                    break;
                case ICMP_UNREACH_PORT:
                    printf("Port Unreachable, ");
                    break;
                default:
                    printf("Unknown code, %u ", icmp_header->icmp_code);
                    break;
            }
            break;
        case ICMP_TIMXCEED:
            printf("Time Exceeded:  ");
            if (icmp_header->icmp_code == ICMP_TIMXCEED_INTRANS)
                printf("TTL Expired in Transit, ");
            else if (icmp_header->icmp_code == ICMP_TIMXCEED_REASS)
                printf("Fragment Reassembly Time Exceeded, ");
            else
                printf("Unknown code %u, ", icmp_header->icmp_code);
            break;
        default:
            printf("Other ICMP Type, ");
            break;
    }
}

// Function to parse the ICMP header and display relevant information
void parse_icmp(const u_char *packet, size_t header_size) {
    // Extract ICMP header from the packet
    const struct icmp *icmp_header = (const struct icmp *)(packet + header_size);

    // Display ICMP header information
    printf("ICMP: ");
    handle_icmp_type(icmp_header);
    printf("Length: %zu, ", packet_size - header_size);
    if(verbosity >= MEDIUM) printf("Checksum: 0x%04x ", ntohs(icmp_header->icmp_cksum));

    // Call the function to handle ICMP type
}