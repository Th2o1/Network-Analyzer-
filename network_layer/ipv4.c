#include "ipv4.h"


void print_ipv4_options(const u_char *options, size_t size) {
    printf("Options: ");
    size_t i = 0;
    while (i < size) {
        uint8_t opt_type = options[i];
        if (opt_type == OPT_EOL) {
            printf("[EOL] ");
            break;
        } else if (opt_type == OPT_NOP) {
            printf("[NOP] ");
            i++;
            continue;
        }
        if (i + 1 >= size) {
            printf("Malformed Option (type: %d) ", opt_type);
            break;
        }
        uint8_t opt_len = options[i + 1];
        if (opt_len < 2 || i + opt_len > size) {
            printf("Malformed Option (type: %d, length: %d) ", opt_type, opt_len);
            break;
        }
        switch (opt_type) {
            case OPT_COS:
                printf("[CS] ");
                break;
            case OPT_RR:
                printf("[RR] ");
                for (size_t j = 2; j < opt_len; j += 4) {
                    struct in_addr addr;
                    memcpy(&addr, &options[i + j], 4);
                    printf("Route: %s ", inet_ntoa(addr));
                }
                break;
            case OPT_TS:
                printf("[TS] ");
                for (size_t j = 2; j < opt_len; j += 4) {
                    uint32_t ts;
                    memcpy(&ts, &options[i + j], 4);
                    printf("Time: %u ms ", ntohl(ts));
                }
                break;
            case OPT_LSR:
                printf("[LSR] ");
                for (size_t j = 2; j < opt_len; j += 4) {
                    struct in_addr addr;
                    memcpy(&addr, &options[i + j], 4);
                    printf("Route: %s ", inet_ntoa(addr));
                }
                break;
            case OPT_SSR:
                printf("[SSR] ");
                for (size_t j = 2; j < opt_len; j += 4) {
                    struct in_addr addr;
                    memcpy(&addr, &options[i + j], 4);
                    printf("Route: %s ", inet_ntoa(addr));
                }
                break;
            default:
                printf("[Unknown] Type: %d ", opt_type);
                break;
        }
        i += opt_len;
    }
}


// Debugging
void print_raw_ip_header(const unsigned char *packet, size_t size) {
    printf("Raw IP Header: ");
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) { 
            printf(" ");
        }
    }
    printf(" ");
}

void check_ipv4_flags(const struct ip *ip_header) {
    uint16_t flags_and_offset = ntohs(ip_header->ip_off); // Conversion to host byte order
    printf("Flags [");
    int flag_before = 0; 
    // Bit 0 (Reserved Flag - RF)
    if (((flags_and_offset & 0x8000) >> 15) == 1) {
        printf("RF");
        flag_before = 1;
    }

    // Bit 1 (Don't Fragment - DF)
    if (((flags_and_offset & 0x4000) >> 14) == 1) {
        if (flag_before) printf(" ");
        printf("DF");
        flag_before = 1;
    }

    // Bit 2 (More Fragments - MF)
    if (((flags_and_offset & 0x2000) >> 13) == 1) {
        if (flag_before) printf(" ");
        printf("MF");
    }

    printf("] ");
    if (verbosity == HIGH){
        uint16_t fragment_offset = flags_and_offset & 0x1FFF; // Bits 3 à 15
        printf("Fragment Offset: %d (bytes: %d) ", fragment_offset, fragment_offset * 8);
    }
}


void parse_IPv4(const u_char *packet){
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    if(verbosity == LOW){
        printf("IPv4 ");
    }
    else{
        printf("IPv4 (");
        //print_raw_ip_header((unsigned char*)ip_header, ip_header->ip_hl * 4);
        char* protocol = ip_header->ip_p == 6 ? "TCP" : "UDP"; //TCP has value 6 and UDP has value 17
        printf("TTL: %d, Protocol: %s (%d) ", ip_header->ip_ttl, protocol, ip_header->ip_p); 
        printf("Version: %d ", ip_header->ip_v);             // IP version
        printf("Header Length: %d bytes ", ip_header->ip_hl * 4); // Header length in bytes
        printf("Type of Service: %d ", ip_header->ip_tos);   // Type of service
        printf("Total Length: %d ", ntohs(ip_header->ip_len)); // Total length of the packet
        printf("Identification: %d ", ntohs(ip_header->ip_id)); // Identification
        check_ipv4_flags(ip_header);                          // Flag
        printf("TTL: %d ", ip_header->ip_ttl);                // Time to live
        // Checksum
        uint16_t calc_checksum = checksum_calc(ip_header, ip_header->ip_hl * 4);
        printf("Checksum: 0x%04x (%s) ",
               ntohs(ip_header->ip_sum),
               (calc_checksum == 0x0000) ? "valid" : "invalid");
        printf("Source Address: %s ", inet_ntoa(ip_header->ip_src)); // Source IP address
        printf("Destination Address: %s", inet_ntoa(ip_header->ip_dst)); // Destination IP address
        printf(") ");
    }
    if(ip_header->ip_hl * 4 > 20 && verbosity == HIGH){ // If Size > 20 we have option
        //print_ipv4_options((const u_char *)(packet + 20 + sizeof(struct ether_header)), packet_size - 20 - sizeof(struct ether_header));
    }

    parse_protocol(ip_header->ip_p, packet,  (ip_header->ip_hl *4) + sizeof(struct ether_header));
    
}