#ifndef LINK
#define LINK

//All include
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h> // Pour en-tête IP
#include <net/ethernet.h> // Détection IPv4 / IPv6 


//Fonction Header
void parse_packet(const u_char *packet, int* verb);
void parse_IPv4(struct ip *ip_header, int verbosity);
void parse_IPv6(struct ip *ip_header, int verbosity);
void parse_ARP(struct ip *ip_header, int verbosity);



#endif // LINK 