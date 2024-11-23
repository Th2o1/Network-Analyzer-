#ifndef LINK
#define LINK

//All include
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h> // IP Header 
#include <net/ethernet.h> // Detection IPv4 / IPv6 
#include "transport_layer.h"


//Fonction Header

void parse_packet(const u_char *packet);
void parse_IPv4(const u_char *packet);
void parse_IPv6(const u_char *packet);
void parse_ARP(const u_char *packet);



#endif // LINK 