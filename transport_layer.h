#ifndef TRANSPORT_LAYER
#define TRANSPORT_LAYER

//Include 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>

// Define for verbosity 
#define LOW 1 
#define MEDIUM 2
#define HIGN 3



// Function Header 

// Check protocol
void parse_protocol(u_char Protocol, const u_char *packet, int verbosity);
void parse_tcp(const u_char *packet, int verbosity);
void parse_udp(const u_char *packet, int verbosity);
void parse_icmp(const u_char *packet, int verbosity);
void check_tcp_flags(uint8_t flags); 

#endif // TRANSPORT_LAYER

