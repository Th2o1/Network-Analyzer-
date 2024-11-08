#include "transport_layer.h"

void parse_tcp(const u_char *packet, int verbosity){
    struct tcphdr *tcp_header = (struct tcphdr *)packet;
    printf("TCP: source %d destination %d \n", ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport));
    return;
}
void parse_udp(const u_char *packet, int verbosity){
    return; 
}
void parse_icmp(const u_char *packet, int verbosity){
    return; 
}

void parse_protocol(u_char protocol, const u_char *packet, int verbosity){
    // we search wich protocol we have 
    switch (protocol) {
        case IPPROTO_TCP: // TCP
            parse_tcp(packet, verbosity);
            break;
        case IPPROTO_UDP: // UDP
            parse_udp(packet, verbosity);
            break;
        case IPPROTO_ICMP: //IMCP
            parse_icmp(packet, verbosity);
            break;
    }
}