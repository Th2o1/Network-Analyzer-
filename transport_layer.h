#ifndef TRANSPORT_LAYER
#define TRANSPORT_LAYER
//Include 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include "global_value.h"
#include "tcp_utils.h"

// Function Header 

// Check protocol
void parse_protocol(u_char Protocol, const u_char *packet);

void parse_tcp(const u_char *packet);

void parse_udp(const u_char *packet);
void parse_icmp(const u_char *packet);
void check_tcp_flags(uint8_t flags); 

#endif // TRANSPORT_LAYER

