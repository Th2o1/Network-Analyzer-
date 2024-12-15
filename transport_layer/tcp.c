#include "tcp.h"



// Use all the other function to parse a TCP packet
void parse_tcp(const u_char *packet, size_t header_size){

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + header_size);
    //print_packet(packet, header_size+(tcp_header->th_off*4));
    printf("TCP Source %u Destination %u ", 
        ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport));
    printf("Sequence %u Ack %u ", 
        ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack));
    printf("Data offset %u ", tcp_header->th_off);
    printf("%u ", checksum_calc(tcp_header, header_size+(tcp_header->th_off*4)));
    check_tcp_flags(tcp_header->th_flags);
    // Print Window
    printf("Window %u ", tcp_header->th_win);

    // Print Checksum and its validity
    printf("%u %d ", checksum_calc(packet, header_size + (tcp_header->th_off * 4)), header_size);
    printf("Checksum %u (%s) ", tcp_header->th_sum, 
           (checksum_calc(packet, header_size + (tcp_header->th_off * 4)) == 0x0000) ? "valid" : "invalid");

    // Print Urgent Pointer
    printf("Urgent Pointer %u\n", tcp_header->th_urp);
    if(tcp_header->th_off > 5){
        // tcp packet is 20 octet after that its only option
        const u_char* tcp_options = (const u_char*) tcp_header + 20;
        // Size in octet of the option
        unsigned int options_size = (tcp_header->th_off * 4) - 20;
        check_tcp_options(tcp_options, options_size);
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
