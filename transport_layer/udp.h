#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <netinet/ip.h> // IP Header 
#include <string.h>

#include "../application_layer/bootp_dhcp.h"
#include "../application_layer/dns.h"
#include "../global_value.h"


void parse_udp(const u_char *packet,size_t header_size);