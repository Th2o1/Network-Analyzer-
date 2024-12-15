#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <netinet/ip.h> // IP Header 
#include <string.h>

#include "../global_value.h"


void parse_udp(const u_char *packet,size_t header_size);