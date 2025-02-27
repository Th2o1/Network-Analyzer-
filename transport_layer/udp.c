#include "udp.h"

//Function to validate UDP checksum
uint16_t validate_udp_checksum(const struct ip *ip_header, const struct udphdr *udp_header, size_t udp_length) {
    // Compute the length of the pseudo-header and UDP data
    uint16_t pseudo_header_len = 12 + udp_length;

    // Allocate memory for the pseudo-header
    uint8_t pseudo_header[pseudo_header_len];

    // Initialize pseudo-header with zero
    memset(pseudo_header, 0, pseudo_header_len);

    // Fill the pseudo-header with source and destination IP addresses
    memcpy(pseudo_header, &ip_header->ip_src, sizeof(ip_header->ip_src));
    memcpy(pseudo_header + 4, &ip_header->ip_dst, sizeof(ip_header->ip_dst));

    // Fill protocol and UDP length fields
    pseudo_header[8] = 0; // Reserved
    pseudo_header[9] = IPPROTO_UDP; // Protocol UDP
    pseudo_header[10] = (udp_length >> 8) & 0xFF; // UDP length high byte
    pseudo_header[11] = udp_length & 0xFF; // UDP length low byte

    // Copy the UDP header and data into the pseudo-header
    memcpy(pseudo_header + 12, udp_header, udp_length);

    // Compute and return the checksum
    return checksum_calc(pseudo_header, pseudo_header_len);
}


void parse_udp(const u_char *packet, size_t header_size) {
    // Extract the UDP header from the packet
    struct udphdr *udp_header = (struct udphdr *)(packet + header_size);

    // Extract source port, destination port, length, and checksum from the header
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    uint16_t udp_length = ntohs(udp_header->uh_ulen);
    uint16_t udp_checksum = ntohs(udp_header->uh_sum);

    // Print basic UDP information
    printf("UDP: ");
    printf("%u > %u, ", src_port, dst_port);
    if ((verbosity >= MEDIUM))
    {
        printf("Length: %u, ", udp_length);
    }
    

    // Get the IP header for checksum calculation
    struct ip *ip_header = (struct ip *)(packet+sizeof(struct ether_header));

    // Call the checksum validation function
    uint16_t calculated_checksum = validate_udp_checksum(ip_header, udp_header, udp_length);

    // Print checksum result
    printf("Checksum: 0x%04x (%s) ", udp_checksum,
           (calculated_checksum == 0x0000) ? "valid" : "invalid");
    if(verbosity == HIGH){
        printf("\n");
    }

    // We detect bootp with the port
    if (src_port == 67 || src_port == 68){
        parse_bootp(packet, header_size + sizeof(struct udphdr));
    }

    // We detect DNS with port 
    if (src_port == 53 || dst_port == 53){
        parse_dns(packet, header_size + sizeof(struct udphdr));
    }

    

    return;
}


