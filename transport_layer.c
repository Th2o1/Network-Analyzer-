#include "transport_layer.h"


void parse_tcp(const u_char *packet){
    struct tcphdr *tcp_header = (struct tcphdr *)packet;
    display_tcp_header(tcp_header);
    if(tcp_header->th_off > 5){
        // tcp packet is 20 octet after that its only option
        const u_char* tcp_options = (const u_char*) tcp_header + 20;
        // Size in octet of the option
        unsigned int options_size = (tcp_header->th_off * 4) - 20;
        check_tcp_options(tcp_options, options_size);
    }
    printf("\n");
    return;
}
void parse_udp(const u_char *packet){
    return; 
}
void parse_icmp(const u_char *packet){
    return; 
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
    }
}