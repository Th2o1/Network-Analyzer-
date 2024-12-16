#ifndef ICMPV6_PARSING
#define ICMPV6_PARSING

#include <netinet/icmp6.h> 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h> // IP Header 
#include "../global_value.h"

//PARSING
void parse_icmpv6(const u_char *packet, size_t header_size);

#endif