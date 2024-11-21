#include "transport_layer.h"

void check_tcp_flags(uint8_t flags) {
    printf("Flags TCP détectés :");

    if (flags & TH_FIN) printf(" FIN");
    if (flags & TH_SYN) printf(" SYN");
    if (flags & TH_RST) printf(" RST");
    if (flags & TH_PUSH) printf(" PSH");
    if (flags & TH_ACK) printf(" ACK");
    if (flags & TH_URG) printf(" URG");
    if (flags & TH_ECE) printf(" ECE");
    if (flags & TH_CWR) printf(" CWR");

    printf("\n");
}


void parse_tcp(const u_char *packet, int verbosity){
    struct tcphdr *tcp_header = (struct tcphdr *)packet;
    printf("TCP: source %d destination %d \n", ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport));
    check_tcp_flags(tcp_header->th_flags);
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