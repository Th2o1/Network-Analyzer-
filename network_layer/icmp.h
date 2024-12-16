#ifndef ICMP_PARSING
#define ICMP_PARSING

#include <netinet/ip_icmp.h> 
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ip.h> // IP Header 
#include "../global_value.h"


void parse_icmp(const u_char *packet, size_t header_size);


#endif