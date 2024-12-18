#include "tcp.h"

uint16_t validate_tcp_checksum(const struct ip *ip_header, const struct tcphdr *tcp_header) {
    // Calculate the length of the pseudo-header and the TCP data
    size_t pseudo_header_len = 12 + (tcp_header->th_off * 4);

    // Allocate memory for the pseudo-header
    uint8_t pseudo_header[pseudo_header_len];

    // Initialize the pseudo-header with zeros
    memset(pseudo_header, 0, pseudo_header_len);

    // Copy the source and destination addresses from the IP header
    memcpy(pseudo_header, &ip_header->ip_src, sizeof(ip_header->ip_src));
    memcpy(pseudo_header + 4, &ip_header->ip_dst, sizeof(ip_header->ip_dst));

    // Fill the protocol field and the pseudo-header length
    pseudo_header[8] = 0; // reserved
    pseudo_header[9] = IPPROTO_TCP; // Protocol TCP
    pseudo_header[10] = (pseudo_header_len >> 8) & 0xFF; // Pseudo-header length (high byte)
    pseudo_header[11] = pseudo_header_len & 0xFF; // Pseudo-header length (low byte)

    // Copy the TCP header and data into the pseudo-header
    memcpy(pseudo_header + 12, tcp_header, (tcp_header->th_off * 4));

    // Calculate and return the checksum
    return checksum_calc(pseudo_header, pseudo_header_len);
}

// Use all the other function to parse a TCP packet
void parse_tcp(const u_char *packet, size_t header_size) {
    // Extract the TCP header from the packet
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + header_size);

    // Extract source port, destination port, sequence number, ack number, data offset, window size, urgent pointer from the header
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    uint8_t sequence_number = tcp_header->th_seq;
    uint8_t ack_number = tcp_header->th_ack;
    uint16_t data_offset = tcp_header->th_off;
    uint16_t window_size = ntohs(tcp_header->th_win);
    uint16_t urgent_pointer = tcp_header->th_urp;

    // Print basic TCP information
    printf("TCP Source %u Destination %u ", src_port, dst_port);
    printf("Sequence %u Ack %u ", sequence_number, ack_number);
    printf("Data offset %u ", data_offset);

    // Call the checksum validation function
    struct ip *ip_header = (struct ip *)packet;
    uint16_t calculated_checksum = validate_tcp_checksum(ip_header, tcp_header);
    printf("CLAC : 0x%04x ", calculated_checksum);

    // Print checksum result
    printf("Checksum 0x%04x (%s) ", tcp_header->th_sum,
           (calculated_checksum == 0x0000) ? "valid" : "invalid");

    // Check TCP flags
    check_tcp_flags(tcp_header->th_flags);

    // Print Window Size
    printf("Window %u ", window_size);

    // Print Urgent Pointer
    printf("Urgent Pointer %u ", urgent_pointer);

    // Check TCP options
    if (data_offset > 5) {
        const u_char* tcp_options = (const u_char*) tcp_header + 20;
        unsigned int options_size = (data_offset * 4) - 20;
        check_tcp_options(tcp_options, options_size);
    }

    // Calc the offset for the next layer
    size_t tcp_header_size = data_offset * 4;
    size_t offset =  header_size + tcp_header_size;

    // Check for SMTP traffic based on port
    if (src_port == 25 || dst_port == 25 || 
        src_port == 587 || dst_port == 587 || 
        src_port == 465 || dst_port == 465) {
        printf("SMTP ");
        if (packet_size-offset != 0) parse_ascii(packet, offset);
    }
    // Check for HTTP traffic based on port 
    if (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080 ||
        src_port == 443 || dst_port == 443 ){
        printf("HTTP");
        if (packet_size-offset != 0) printf(": Length: %zu",packet_size-offset);
    }
    // Check for FTP based on port 
    if (src_port == 21 || dst_port == 21){
        printf("FTP: ");
        if (packet_size-offset != 0) parse_ascii(packet, offset);
    }
    // Check for IMAP based on port 
    if (src_port == 143 || dst_port == 143){
        printf("IMAP ");
        if (packet_size-offset != 0)parse_ascii(packet, offset);
    }

    return;
}


// Print every flags of the tcp packet
void check_tcp_flags(uint8_t flags) {
    if(!(flags & TH_FLAGS)){
        return;
    }
    printf("Flags:");
    if (flags & TH_FIN) printf(" FIN");
    if (flags & TH_SYN) printf(" SYN");
    if (flags & TH_RST) printf(" RST");
    if (flags & TH_PUSH) printf(" PSH");
    if (flags & TH_ACK) printf(" ACK");
    if (flags & TH_URG) printf(" URG");
    if (flags & TH_ECE) printf(" ECE");
    if (flags & TH_CWR) printf(" CWR");
    printf(" ");

    return;

    
}
// Print all the option of tcp
void check_tcp_options(const u_char* tcp_options ,unsigned int options_size){
    u_char kind;
    u_char length;
    char* option_name ="";
    while (options_size > 0) {
        kind = *tcp_options;
        length = *(tcp_options + 1);
        // To find out which option you're facing 
        switch (kind)
        {
        case TCPOPT_EOL: // End of option
            option_name = "End of Options List (EOL)";
            length = 1; //  No specif length
            break;
        case TCPOPT_NOP: // No operation
            option_name = "No-Operation (NOP)";
            length = 1; // No specif length
            break;
        case TCP_MAXSEG: //
            option_name = "Max segs (MSS) ";
            break;
        case TCPOPT_WINDOW: // Window Scale
            option_name = "Window Scale";
            break;
        case TCPOPT_SACK_PERMITTED: // SACK Permitted
            option_name = "Selective Acknowledgment Permitted (SACK)";
            break;
        case TCPOPT_SACK: // SACK
            option_name = "Selective Acknowledgment (SACK)";
            break;
        case TCPOPT_TIMESTAMP: // Timestamp
            option_name = "Timestamp Option";
            break;
        default:
            option_name = "Unknown Option";
            length = *(tcp_options + 1);
            if (options_size > 1) {
                length = *(tcp_options + 1); 
            } else {
                length = 1; // Too avoid loop
            }
            break;
        }
        // Display the option
        printf("Option: %s (Kind = %u, Length = %u) ", option_name, kind, length);

        // Check the length
        if (length < 1 || length > options_size) {
            printf("Erreur: Longueur d'option invalide (%u)\n", length);
            break; // Avoid infinite loop
        }
        // Decrease size left and moving the pointer 
        options_size -= length;
        tcp_options += length;
    }
    return ;
}
